from fastapi import FastAPI, HTTPException, Request, Body
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
import traceback
from fastapi import APIRouter

app = FastAPI(title="端口转发管理系统")

router = APIRouter()

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应该设置为特定域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# 端口规则模型
class PortRule(BaseModel):
    target_ip: str
    port_start: int = Field(..., ge=10000, le=65535)
    port_end: int = Field(..., ge=10000, le=65535)
    description: Optional[str] = ""
    iptables_commands: Optional[List[Dict[str, str]]] = None

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
        print(f"Executing: {command}")  # 增加日志
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing: {command}\n{e.stderr}")  # 增加日志
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

# 定义全局规则
GLOBAL_RULES = [
    {"create": "iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o tun0 -j TCPMSS --clamp-mss-to-pmtu",
     "delete": "iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -o tun0 -j TCPMSS --clamp-mss-to-pmtu"},
    {"create": "iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
     "delete": "iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"},
    {"create": "iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE",
     "delete": "iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE"},
    {"create": "iptables -t nat -A POSTROUTING -o ens33 -s 192.168.0.0/16 -j MASQUERADE",
     "delete": "iptables -t nat -D POSTROUTING -o ens33 -s 192.168.0.0/16 -j MASQUERADE"},
    {"create": "iptables -A FORWARD -i ens33 -o tun0 -m conntrack --ctstate NEW -j ACCEPT",
     "delete": "iptables -D FORWARD -i ens33 -o tun0 -m conntrack --ctstate NEW -j ACCEPT"}
]

# 应用全局规则 (如果不存在)
def apply_global_rules_if_needed():
    applied_new = False
    for rule in GLOBAL_RULES:
        check_cmd = rule['create'].replace(" -A ", " -C ")
        success, _ = execute_iptables_command(check_cmd)
        if not success:
            apply_success, output = execute_iptables_command(rule['create'])
            if not apply_success:
                print(f"警告：应用全局规则失败: {rule['create']} - {output}")
            else:
                applied_new = True
    return applied_new

# 移除全局规则 (如果不再需要)
def remove_global_rules_if_empty(remaining_rules_count):
    if remaining_rules_count == 0:
        print("没有剩余规则，正在移除全局iptables规则...")
        for rule in reversed(GLOBAL_RULES):
            success, output = execute_iptables_command(rule['delete'])
            if not success:
                print(f"警告：移除全局规则失败: {rule['delete']} - {output}")

# 创建特定端口的iptables规则
def create_specific_iptables_rules(rule_data):
    target_ip = rule_data['target_ip']
    port_start = rule_data['port_start']
    port_end = rule_data['port_end']

    specific_rules_commands = [
        {"create": f"iptables -t nat -A PREROUTING -i tun0 -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}",
         "delete": f"iptables -t nat -D PREROUTING -i tun0 -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"},
        {"create": f"iptables -t nat -A OUTPUT -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}",
         "delete": f"iptables -t nat -D OUTPUT -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_ip}"},
        {"create": f"iptables -A FORWARD -i tun0 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT",
         "delete": f"iptables -D FORWARD -i tun0 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT"},
        {"create": f"iptables -A FORWARD -i ens33 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT",
         "delete": f"iptables -D FORWARD -i ens33 -o ens33 -d {target_ip} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT"},
        {"create": f"iptables -t nat -A POSTROUTING -p tcp -d {target_ip} --dport {port_start}:{port_end} -j MASQUERADE",
         "delete": f"iptables -t nat -D POSTROUTING -p tcp -d {target_ip} --dport {port_start}:{port_end} -j MASQUERADE"}
    ]

    applied_commands = []
    try:
        for cmd_pair in specific_rules_commands:
            success, output = execute_iptables_command(cmd_pair['create'])
            if not success:
                print(f"创建规则失败: {cmd_pair['create']}, 开始回滚...")
                for applied_cmd in reversed(applied_commands):
                    execute_iptables_command(applied_cmd['delete'])
                return False, f"创建规则失败: {cmd_pair['create']} - {output}", None
            applied_commands.append(cmd_pair)

        return True, "特定规则创建成功", applied_commands

    except Exception as e:
        print(f"创建规则时发生意外错误: {e}, 开始回滚...")
        for applied_cmd in reversed(applied_commands):
            execute_iptables_command(applied_cmd['delete'])
        return False, f"创建规则时发生意外错误: {traceback.format_exc()}", None

# 删除特定端口的iptables规则 (使用存储的命令)
def delete_specific_iptables_rules(rule_data):
    commands_to_delete = rule_data.get('iptables_commands')
    if not commands_to_delete:
        return False, "规则数据中未找到iptables_commands，无法删除"

    failed_deletions = []
    for cmd_pair in reversed(commands_to_delete):
        delete_cmd = cmd_pair.get('delete')
        if delete_cmd:
            success, output = execute_iptables_command(delete_cmd)
            if not success:
                failed_deletions.append(f"删除失败: {delete_cmd} - {output}")
        else:
            failed_deletions.append(f"警告: 规则缺少删除命令: {cmd_pair.get('create')}")

    if failed_deletions:
        return False, "部分特定规则删除失败:\n" + "\n".join(failed_deletions)

    return True, "特定规则删除成功"

# API路由
@app.get("/api/rules")
async def get_rules():
    # 查询系统iptables规则并返回结构化数据
    nat_rules = subprocess.run(
        "iptables -t nat -S", shell=True, capture_output=True, text=True
    ).stdout.splitlines()
    rules = []
    for rule in nat_rules:
        # 只处理 DNAT 端口转发规则
        # 示例: -A PREROUTING -i tun0 -p tcp -m tcp --dport 10000:10005 -j DNAT --to-destination 192.168.31.128
        import re
        m = re.search(r"--dport (\d+)(?::(\d+))? -j DNAT --to-destination ([0-9.]+)", rule)
        if m:
            port_start = int(m.group(1))
            port_end = int(m.group(2)) if m.group(2) else int(m.group(1))
            target_ip = m.group(3)
            rules.append({
                "target_ip": target_ip,
                "port_start": port_start,
                "port_end": port_end,
                "description": ""
            })
    return rules

@app.get("/api/network/tun0-ip", response_model=Dict[str, Optional[str]])
async def get_tun0_ip_route():
    ip = get_tun0_ip()
    return {"ip": ip}

@app.post("/api/rules")
async def create_rule(rule: PortRule):
    rules = load_rules()

    if not is_port_range_available(rule.port_start, rule.port_end, rules):
        raise HTTPException(status_code=400, detail="端口范围已被占用")

    if len(rules) == 0:
        print("这是第一条规则，尝试应用全局iptables规则...")
        apply_global_rules_if_needed()

    rule_dict = rule.dict(exclude_unset=True)
    success, message, applied_commands = create_specific_iptables_rules(rule_dict)

    if not success:
        raise HTTPException(status_code=500, detail=message)

    rule_dict['iptables_commands'] = applied_commands
    rules.append(rule_dict)
    save_rules(rules)

    return rule_dict

@app.delete("/api/rules/{port_start}/{port_end}")
async def delete_rule(port_start: int, port_end: int):
    rules = load_rules()

    rule_to_delete = None
    rule_index = -1
    for i, r in enumerate(rules):
        if r['port_start'] == port_start and r['port_end'] == port_end:
            rule_to_delete = r
            rule_index = i
            break

    if rule_index == -1 or rule_to_delete is None:
        raise HTTPException(status_code=404, detail="规则不存在")

    success, message = delete_specific_iptables_rules(rule_to_delete)
    if not success:
        print(f"删除iptables规则时出错，但仍将从JSON移除记录: {message}")

    deleted_rule_data = rules.pop(rule_index)
    save_rules(rules)

    remove_global_rules_if_empty(len(rules))

    if not success:
        raise HTTPException(status_code=500, detail=f"部分iptables规则删除失败，但记录已从配置移除: {message}")

    return deleted_rule_data

@app.post("/api/iptables/delete")
async def delete_iptables_rule(rule: str = Body(...)):
    # 只允许删除以 -A 开头的规则
    if not rule.startswith("-A "):
        return {"error": "只能删除-A开头的规则"}
    # 替换-A为-D
    delete_cmd = rule.replace("-A ", "-D ", 1)
    result = subprocess.run(
        f"iptables -t nat {delete_cmd}", shell=True, capture_output=True, text=True
    )
    if result.returncode == 0:
        return {"success": True}
    else:
        return {"success": False, "error": result.stderr}

@router.get("/api/iptables/rules")
async def list_iptables_rules():
    # 获取 NAT 表规则
    nat_rules = subprocess.run(
        "iptables -t nat -S", shell=True, capture_output=True, text=True
    ).stdout.splitlines()
    # 获取 FORWARD 链规则
    forward_rules = subprocess.run(
        "iptables -S FORWARD", shell=True, capture_output=True, text=True
    ).stdout.splitlines()

    # 只筛选端口转发相关的规则（如 -A PREROUTING ... --dport ... -j DNAT ...）
    port_forward_rules = []
    for rule in nat_rules + forward_rules:
        if "--dport" in rule or "-j DNAT" in rule or "-j MASQUERADE" in rule:
            port_forward_rules.append(rule)

    return {"rules": port_forward_rules}

@app.middleware("http")
async def errors_handling(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"detail": f"服务器内部错误: {str(exc)}"},
        )

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)