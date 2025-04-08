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
    
    # 创建DNAT规则
    dnat_cmd = f"iptables -t nat -A PREROUTING -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"
    success, output = execute_iptables_command(dnat_cmd)
    if not success:
        return False, f"DNAT规则创建失败: {output}"
    
    # 创建MASQUERADE规则
    masq_cmd = f"iptables -t nat -A POSTROUTING -p tcp -d {target_ip} --dport {port_start}:{port_end} -j MASQUERADE"
    success, output = execute_iptables_command(masq_cmd)
    if not success:
        # 回滚之前的规则
        rollback_cmd = f"iptables -t nat -D PREROUTING -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"
        execute_iptables_command(rollback_cmd)
        return False, f"MASQUERADE规则创建失败: {output}"
    
    return True, "规则创建成功"

# 删除iptables规则
def delete_iptables_rules(rule):
    target_ip = rule['target_ip']
    port_start = rule['port_start']
    port_end = rule['port_end']
    
    # 删除DNAT规则
    dnat_cmd = f"iptables -t nat -D PREROUTING -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"
    success, output = execute_iptables_command(dnat_cmd)
    if not success:
        return False, f"DNAT规则删除失败: {output}"
    
    # 删除MASQUERADE规则
    masq_cmd = f"iptables -t nat -D POSTROUTING -p tcp -d {target_ip} --dport {port_start}:{port_end} -j MASQUERADE"
    success, output = execute_iptables_command(masq_cmd)
    if not success:
        return False, f"MASQUERADE规则删除失败: {output}"
    
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