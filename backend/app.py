from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator, Field
from typing import List, Optional, Dict
import subprocess
import re
import ipaddress
import os
import json
from pathlib import Path

app = FastAPI(title="端口转发管理系统")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应该设置为特定域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 数据存储路径
DATA_DIR = Path(os.path.dirname(os.path.abspath(__file__))) / "data"
DATA_FILE = DATA_DIR / "port_rules.json"

# 确保数据目录存在
DATA_DIR.mkdir(exist_ok=True)

# 端口规则模型
class PortRule(BaseModel):
    target_ip: str
    port_start: int = Field(..., ge=10000, le=65535)
    port_end: int = Field(..., ge=10000, le=65535)
    description: Optional[str] = ""
    
    @validator('target_ip')
    def validate_ip(cls, v):
        try:
            ipaddress.IPv4Address(v)
            return v
        except ValueError:
            raise ValueError('无效的IPv4地址')
    
    @validator('port_end')
    def validate_port_range(cls, v, values):
        if 'port_start' in values and v < values['port_start']:
            raise ValueError('结束端口必须大于或等于开始端口')
        
        if 'port_start' in values and (v - values['port_start'] + 1) > 10:
            raise ValueError('端口范围不能超过10个端口')
            
        return v

# 加载现有规则
def load_rules():
    if not DATA_FILE.exists():
        return []
    
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"加载规则文件出错: {e}")
        return []

# 保存规则
def save_rules(rules):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)

# 检查端口是否已被分配
def is_port_range_available(port_start, port_end, rules=None):
    if rules is None:
        rules = load_rules()
    
    for rule in rules:
        rule_start = rule['port_start']
        rule_end = rule['port_end']
        
        # 检查是否有重叠
        if not (port_end < rule_start or port_start > rule_end):
            return False
    
    return True

# 执行iptables命令
def execute_iptables_command(command):
    try:
        # 在生产环境中，应该使用更安全的方式执行命令
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr
        
# 获取tun0网卡IP地址
def get_tun0_ip():
    try:
        # 使用ip命令获取tun0网卡信息
        command = "ip addr show tun0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1"
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        ip = result.stdout.strip()
        if ip:
            return ip
        return None
    except subprocess.CalledProcessError:
        # tun0网卡不存在或无法获取IP
        return None

# 创建iptables规则
def create_iptables_rules(rule):
    target_ip = rule['target_ip']
    port_start = rule['port_start']
    port_end = rule['port_end']
    
    # 用于存储已创建的规则，以便在失败时回滚
    created_rules = []
    
    # 创建DNAT规则 - VPN流量
    dnat_vpn_cmd = f"iptables -t nat -A PREROUTING -i tun0 -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"
    success, output = execute_iptables_command(dnat_vpn_cmd)
    if not success:
        return False, f"VPN DNAT规则创建失败: {output}"
    created_rules.append(("nat", "PREROUTING", f"-i tun0 -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"))
    
    # 创建DNAT规则 - 本地流量
    dnat_local_cmd = f"iptables -t nat -A OUTPUT -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"
    success, output = execute_iptables_command(dnat_local_cmd)
    if not success:
        # 回滚之前的规则
        for table, chain, rule_spec in created_rules:
            rollback_cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(rollback_cmd)
        return False, f"本地DNAT规则创建失败: {output}"
    created_rules.append(("nat", "OUTPUT", f"-p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"))
    
    # 创建FORWARD规则 - VPN到内网
    forward_vpn_cmd = f"iptables -A FORWARD -i tun0 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT"
    success, output = execute_iptables_command(forward_vpn_cmd)
    if not success:
        # 回滚之前的规则
        for table, chain, rule_spec in created_rules:
            rollback_cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(rollback_cmd)
        return False, f"VPN FORWARD规则创建失败: {output}"
    created_rules.append(("filter", "FORWARD", f"-i tun0 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT"))
    
    # 创建FORWARD规则 - 内网本地
    forward_local_cmd = f"iptables -A FORWARD -i ens33 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT"
    success, output = execute_iptables_command(forward_local_cmd)
    if not success:
        # 回滚之前的规则
        for table, chain, rule_spec in created_rules:
            rollback_cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(rollback_cmd)
        return False, f"本地FORWARD规则创建失败: {output}"
    created_rules.append(("filter", "FORWARD", f"-i ens33 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT"))
    
    # 创建MASQUERADE规则 - 特定端口的流量伪装
    masq_cmd = f"iptables -t nat -A POSTROUTING -p tcp -d {target_ip} --dport {port_start}:{port_end} -j MASQUERADE"
    success, output = execute_iptables_command(masq_cmd)
    if not success:
        # 回滚所有之前的规则
        for table, chain, rule_spec in created_rules:
            rollback_cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(rollback_cmd)
        return False, f"MASQUERADE规则创建失败: {output}"
    created_rules.append(("nat", "POSTROUTING", f"-p tcp -d {target_ip} --dport {port_start}:{port_end} -j MASQUERADE"))
    
    # 添加MSS调整规则（解决MTU问题）
    mss_cmd = f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o tun0 -j TCPMSS --clamp-mss-to-pmtu"
    success, output = execute_iptables_command(mss_cmd)
    if not success:
        # 回滚所有之前的规则
        for table, chain, rule_spec in created_rules:
            rollback_cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(rollback_cmd)
        return False, f"MSS调整规则创建失败: {output}"
    created_rules.append(("mangle", "FORWARD", f"-p tcp --tcp-flags SYN,RST SYN -o tun0 -j TCPMSS --clamp-mss-to-pmtu"))
    
    # 添加允许已建立/相关的连接规则
    established_cmd = f"iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    success, output = execute_iptables_command(established_cmd)
    if not success:
        # 回滚所有之前的规则
        for table, chain, rule_spec in created_rules:
            rollback_cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(rollback_cmd)
        return False, f"已建立连接规则创建失败: {output}"
    created_rules.append(("filter", "FORWARD", f"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"))
    
    # 添加出站流量伪装规则 - tun0接口
    masq_tun0_cmd = f"iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE"
    success, output = execute_iptables_command(masq_tun0_cmd)
    if not success:
        # 回滚所有之前的规则
        for table, chain, rule_spec in created_rules:
            rollback_cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(rollback_cmd)
        return False, f"tun0出站流量伪装规则创建失败: {output}"
    created_rules.append(("nat", "POSTROUTING", f"-o tun0 -j MASQUERADE"))
    
    # 添加出站流量伪装规则 - ens33接口（本地子网）
    masq_ens33_cmd = f"iptables -t nat -A POSTROUTING -o ens33 -s 192.168.0.0/16 -j MASQUERADE"
    success, output = execute_iptables_command(masq_ens33_cmd)
    if not success:
        # 回滚所有之前的规则
        for table, chain, rule_spec in created_rules:
            rollback_cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(rollback_cmd)
        return False, f"ens33出站流量伪装规则创建失败: {output}"
    created_rules.append(("nat", "POSTROUTING", f"-o ens33 -s 192.168.0.0/16 -j MASQUERADE"))
    
    # 添加允许内网到VPN的初始连接规则
    init_conn_cmd = f"iptables -A FORWARD -i ens33 -o tun0 -m conntrack --ctstate NEW -j ACCEPT"
    success, output = execute_iptables_command(init_conn_cmd)
    if not success:
        # 回滚所有之前的规则
        for table, chain, rule_spec in created_rules:
            rollback_cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(rollback_cmd)
        return False, f"内网到VPN初始连接规则创建失败: {output}"
    created_rules.append(("filter", "FORWARD", f"-i ens33 -o tun0 -m conntrack --ctstate NEW -j ACCEPT"))
    
    return True, "规则创建成功"

# 删除iptables规则
def delete_iptables_rules(rule):
    target_ip = rule['target_ip']
    port_start = rule['port_start']
    port_end = rule['port_end']
    
    # 存储需要删除的规则
    rules_to_delete = [
        # 基本端口转发规则
        ("nat", "PREROUTING", f"-i tun0 -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"),
        ("nat", "OUTPUT", f"-p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"),
        ("filter", "FORWARD", f"-i tun0 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT"),
        ("filter", "FORWARD", f"-i ens33 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT"),
        ("nat", "POSTROUTING", f"-p tcp -d {target_ip} --dport {port_start}:{port_end} -j MASQUERADE")
    ]
    
    # 删除所有规则，记录失败的规则
    failed_rules = []
    for table, chain, rule_spec in rules_to_delete:
        cmd = f"iptables -t {table} -D {chain} {rule_spec}"
        success, output = execute_iptables_command(cmd)
        if not success:
            failed_rules.append((table, chain, rule_spec, output))
    
    # 如果有规则删除失败，返回错误信息
    if failed_rules:
        error_msg = "\n".join([f"{table} {chain} 规则删除失败: {output}" for table, chain, rule_spec, output in failed_rules])
        return False, f"部分规则删除失败:\n{error_msg}"
    
    # 检查是否是最后一个规则，如果是，则删除全局规则
    rules = load_rules()
    if len(rules) <= 1:  # 当前规则是唯一的或最后一个
        # 删除全局规则（这些规则是所有端口转发共享的）
        global_rules = [
            ("mangle", "FORWARD", "-p tcp --tcp-flags SYN,RST SYN -o tun0 -j TCPMSS --clamp-mss-to-pmtu"),
            ("filter", "FORWARD", "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"),
            ("nat", "POSTROUTING", "-o tun0 -j MASQUERADE"),
            ("nat", "POSTROUTING", "-o ens33 -s 192.168.0.0/16 -j MASQUERADE"),
            ("filter", "FORWARD", "-i ens33 -o tun0 -m conntrack --ctstate NEW -j ACCEPT")
        ]
        
        for table, chain, rule_spec in global_rules:
            cmd = f"iptables -t {table} -D {chain} {rule_spec}"
            execute_iptables_command(cmd)  # 即使失败也继续删除其他规则
    
    return True, "规则删除成功"

# API路由
@app.get("/api/rules")
async def get_rules():
    return load_rules()
    
# 获取tun0网卡IP地址
@app.get("/api/network/tun0-ip", response_model=Dict[str, Optional[str]])
async def get_tun0_ip_route():
    ip = get_tun0_ip()
    return {"ip": ip}

@app.post("/api/rules")
async def create_rule(rule: PortRule):
    rules = load_rules()
    
    # 检查端口范围是否可用
    if not is_port_range_available(rule.port_start, rule.port_end, rules):
        raise HTTPException(status_code=400, detail="端口范围已被占用")
    
    # 创建iptables规则
    success, message = create_iptables_rules(rule.dict())
    if not success:
        raise HTTPException(status_code=500, detail=message)
    
    # 保存规则到文件
    rule_dict = rule.dict()
    rules.append(rule_dict)
    save_rules(rules)
    
    return rule_dict

@app.delete("/api/rules/{port_start}/{port_end}")
async def delete_rule(port_start: int, port_end: int):
    rules = load_rules()
    
    # 查找匹配的规则
    rule_index = None
    for i, rule in enumerate(rules):
        if rule['port_start'] == port_start and rule['port_end'] == port_end:
            rule_index = i
            break
    
    if rule_index is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    # 删除iptables规则
    rule = rules[rule_index]
    success, message = delete_iptables_rules(rule)
    if not success:
        raise HTTPException(status_code=500, detail=message)
    
    # 从文件中删除规则
    deleted_rule = rules.pop(rule_index)
    save_rules(rules)
    
    return deleted_rule

# 错误处理中间件
@app.middleware("http")
async def errors_handling(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"detail": f"服务器内部错误: {str(exc)}"},
        )

# 启动服务器
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)