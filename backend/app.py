from fastapi import FastAPI, HTTPException, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator, Field
from typing import List, Optional, Dict
import subprocess
import re
import ipaddress
import os
import traceback
from fastapi import APIRouter

app = FastAPI(title="端口转发管理系统")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

# 检查端口是否已被分配（通过查询现有 iptables 规则）
async def is_port_range_available(port_start, port_end):
    current_rules = await get_rules()
    for rule in current_rules:
        rule_start = rule['port_start']
        rule_end = rule['port_end']
        if not (port_end < rule_start or port_start > rule_end):
            return False
    return True

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
        m = re.search(r"-A PREROUTING -i tun0 -p tcp(?: -m tcp)? --dport (\d+)(?::(\d+))? -j DNAT --to-destination ([0-9.]+)", rule)
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

@app.post("/api/rules")
async def create_rule(rule: PortRule):
    if not await is_port_range_available(rule.port_start, rule.port_end):
        raise HTTPException(status_code=400, detail="端口范围已被占用")

    # 创建 DNAT 规则
    commands = [
        f"iptables -t nat -A PREROUTING -i tun0 -p tcp --dport {rule.port_start}:{rule.port_end} -j DNAT --to-destination {rule.target_ip}",
        f"iptables -t nat -A OUTPUT -p tcp --dport {rule.port_start}:{rule.port_end} -j DNAT --to-destination {rule.target_ip}",
        f"iptables -A FORWARD -i tun0 -o ens33 -d {rule.target_ip} -p tcp --dport {rule.port_start}:{rule.port_end} -m conntrack --ctstate NEW -j ACCEPT",
        f"iptables -A FORWARD -i ens33 -o ens33 -d {rule.target_ip} -p tcp --dport {rule.port_start}:{rule.port_end} -m conntrack --ctstate NEW -j ACCEPT"
    ]

    errors = []
    for cmd in commands:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            errors.append(f"{cmd}: {result.stderr}")
            # 回滚已创建的规则
            for i in range(len(commands)):
                if i >= len(errors):  # 只回滚成功创建的规则
                    rollback_cmd = commands[i].replace("-A", "-D")
                    subprocess.run(rollback_cmd, shell=True)
            raise HTTPException(status_code=500, detail=f"创建规则失败: {'; '.join(errors)}")

    return rule.dict()

@app.delete("/api/rules/{port_start}/{port_end}")
async def delete_rule(port_start: int, port_end: int):
    # 查询现有规则以获取目标IP
    rules = await get_rules()
    target_rule = None
    for rule in rules:
        if rule['port_start'] == port_start and rule['port_end'] == port_end:
            target_rule = rule
            break
    
    if not target_rule:
        raise HTTPException(status_code=404, detail="规则不存在")

    # 删除规则
    commands = [
        f"iptables -t nat -D PREROUTING -i tun0 -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_rule['target_ip']}",
        f"iptables -t nat -D OUTPUT -p tcp --dport {port_start}:{port_end} -j DNAT --to-destination {target_rule['target_ip']}",
        f"iptables -D FORWARD -i tun0 -o ens33 -d {target_rule['target_ip']} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT",
        f"iptables -D FORWARD -i ens33 -o ens33 -d {target_rule['target_ip']} -p tcp --dport {port_start}:{port_end} -m conntrack --ctstate NEW -j ACCEPT"
    ]

    errors = []
    for cmd in commands:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            errors.append(f"{cmd}: {result.stderr}")

    if errors:
        raise HTTPException(status_code=500, detail=f"删除规则时出现错误: {'; '.join(errors)}")

    return {"success": True}

@app.get("/api/network/tun0-ip", response_model=Dict[str, Optional[str]])
async def get_tun0_ip_route():
    try:
        command = "ip addr show tun0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        ip = result.stdout.strip()
        return {"ip": ip if ip else None}
    except subprocess.CalledProcessError:
        return {"ip": None}

@app.middleware("http")
async def errors_handling(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"detail": f"服务器内部错误: {str(exc)}"},
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)