<template>
  <div class="home-container">
    <el-card class="network-info-card" v-if="networkInfo.ip">
      <div class="network-info">
        <span class="info-label">当前网卡IP (tun0):</span>
        <span class="info-value">{{ networkInfo.ip }}</span>
      </div>
    </el-card>
    <el-card class="form-card">
      <template #header>
        <div class="card-header">
          <h2>申请端口转发</h2>
        </div>
      </template>
      <el-form :model="formData" :rules="formRules" ref="ruleFormRef" label-width="120px" status-icon>
        <el-form-item label="目标IP地址" prop="target_ip">
          <el-input v-model="formData.target_ip" placeholder="请输入目标IP地址"></el-input>
        </el-form-item>
        <el-form-item label="起始端口" prop="port_start">
          <el-input-number v-model="formData.port_start" :min="10000" :max="65535" placeholder="10000-65535"></el-input-number>
        </el-form-item>
        <el-form-item label="结束端口" prop="port_end">
          <el-input-number v-model="formData.port_end" :min="10000" :max="65535" placeholder="10000-65535"></el-input-number>
        </el-form-item>
        <el-form-item label="描述信息" prop="description">
          <el-input v-model="formData.description" type="textarea" placeholder="请输入描述信息（可选）"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="submitForm(ruleFormRef)">提交申请</el-button>
          <el-button @click="resetForm(ruleFormRef)">重置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="table-card">
      <template #header>
        <div class="card-header">
          <h2>端口转发规则列表</h2>
          <el-button type="primary" @click="loadRules">刷新</el-button>
        </div>
      </template>
      <el-table :data="rulesList" style="width: 100%" v-loading="loading" row-key="port_start">
        <el-table-column type="expand">
          <template #default="props">
            <div class="iptables-commands">
              <h4>关联的 iptables 命令:</h4>
              <div v-if="props.row.iptables_commands && props.row.iptables_commands.length > 0">
                <ul>
                  <li v-for="(cmd, index) in props.row.iptables_commands" :key="index">
                    <strong>创建:</strong> <pre><code>{{ cmd.create }}</code></pre>
                    <strong>删除:</strong> <pre><code>{{ cmd.delete }}</code></pre>
                  </li>
                </ul>
              </div>
              <div v-else>
                <p>未找到关联的 iptables 命令记录。</p>
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="target_ip" label="目标IP地址" width="180"></el-table-column>
        <el-table-column prop="port_start" label="起始端口" width="120"></el-table-column>
        <el-table-column prop="port_end" label="结束端口" width="120"></el-table-column>
        <el-table-column prop="description" label="描述信息"></el-table-column>
        <el-table-column label="操作" width="120">
          <template #default="scope">
            <el-button type="danger" size="small" @click="deleteRule(scope.row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'

// API基础URL
const API_BASE_URL = '/api'

// 表单数据
const formData = reactive({
  target_ip: '',
  port_start: 10000,
  port_end: 10000,
  description: ''
})

// 表单验证规则
const formRules = {
  target_ip: [
    { required: true, message: '请输入目标IP地址', trigger: 'blur' },
    { pattern: /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/, message: '请输入有效的IP地址', trigger: 'blur' }
  ],
  port_start: [
    { required: true, message: '请输入起始端口', trigger: 'blur' },
    { type: 'number', min: 10000, max: 65535, message: '端口范围为10000-65535', trigger: 'blur' }
  ],
  port_end: [
    { required: true, message: '请输入结束端口', trigger: 'blur' },
    { type: 'number', min: 10000, max: 65535, message: '端口范围为10000-65535', trigger: 'blur' }
  ]
}

// 表单引用
const ruleFormRef = ref(null)

// 规则列表
const rulesList = ref([])
const loading = ref(false)

// 网络信息
const networkInfo = ref({
  ip: null
})

// 加载规则列表
const loadRules = async () => {
  loading.value = true
  try {
    const response = await axios.get(`${API_BASE_URL}/rules`)
    rulesList.value = response.data
  } catch (error) {
    ElMessage.error('加载规则列表失败：' + (error.response?.data?.detail || error.message))
  } finally {
    loading.value = false
  }
}

// 获取tun0网卡IP
const loadNetworkInfo = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/network/tun0-ip`)
    networkInfo.value = response.data
  } catch (error) {
    console.error('获取网卡信息失败：', error)
  }
}

// 提交表单
const submitForm = async (formEl) => {
  if (!formEl) return
  await formEl.validate(async (valid) => {
    if (valid) {
      // 验证端口范围
      if (formData.port_end < formData.port_start) {
        ElMessage.error('结束端口必须大于或等于起始端口')
        return
      }
      
      if ((formData.port_end - formData.port_start + 1) > 10) {
        ElMessage.error('端口范围不能超过10个端口')
        return
      }

      try {
        const response = await axios.post(`${API_BASE_URL}/rules`, formData)
        ElMessage.success('端口转发规则创建成功')
        resetForm(formEl)
        loadRules()
      } catch (error) {
        ElMessage.error('创建规则失败：' + (error.response?.data?.detail || error.message))
      }
    }
  })
}

// 重置表单
const resetForm = (formEl) => {
  if (!formEl) return
  formEl.resetFields()
}

// 删除规则
const deleteRule = (row) => {
  ElMessageBox.confirm(
    `确定要删除端口 ${row.port_start}-${row.port_end} 的转发规则吗？`,
    '警告',
    {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning',
    }
  ).then(async () => {
    try {
      await axios.delete(`${API_BASE_URL}/rules/${row.port_start}/${row.port_end}`)
      ElMessage.success('规则删除成功')
      loadRules()
    } catch (error) {
      ElMessage.error('删除规则失败：' + (error.response?.data?.detail || error.message))
    }
  }).catch(() => {
    // 取消删除
  })
}

// 组件挂载时加载规则列表和网卡信息
onMounted(() => {
  loadRules()
  loadNetworkInfo()
})
</script>

<style scoped>
.home-container {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h2 {
  margin: 0;
  font-size: 18px;
  color: #303133;
}

.form-card {
  margin-bottom: 20px;
}

.table-card {
  margin-bottom: 20px;
}

.network-info-card {
  margin-bottom: 20px;
  background-color: #f0f9eb;
}

.network-info {
  display: flex;
  align-items: center;
}

.info-label {
  font-weight: bold;
  margin-right: 10px;
}

.info-value {
  font-family: monospace;
  font-size: 1.1em;
}

.iptables-commands {
  padding: 10px 20px;
  background-color: #f9f9f9;
  border-radius: 4px;
  margin: 5px 0;
}

.iptables-commands h4 {
  margin-top: 0;
  margin-bottom: 10px;
  font-size: 14px;
  color: #606266;
}

.iptables-commands ul {
  list-style: none;
  padding-left: 0;
  margin: 0;
}

.iptables-commands li {
  margin-bottom: 10px;
  padding-bottom: 10px;
  border-bottom: 1px solid #eee;
}
.iptables-commands li:last-child {
  border-bottom: none;
  margin-bottom: 0;
  padding-bottom: 0;
}

.iptables-commands strong {
  display: block;
  margin-bottom: 3px;
  font-weight: bold;
  font-size: 12px;
}

.iptables-commands pre {
  background-color: #eef1f6;
  padding: 5px 8px;
  border-radius: 3px;
  margin: 0;
  white-space: pre-wrap; /* 允许换行 */
  word-wrap: break-word; /* 强制换行 */
  font-family: monospace;
  font-size: 12px;
  color: #303133;
}

.iptables-commands code {
 font-family: monospace;
}

.iptables-commands p {
  color: #909399;
  font-size: 13px;
}
</style>