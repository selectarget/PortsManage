<template>
  <div class="app-container">
    <el-container>
      <el-header height="60px">
        <div class="header-content">
          <h1>端口转发管理系统</h1>
        </div>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
      <el-footer height="40px">
        <div class="footer-content">
          <p>© 2025 端口转发管理系统</p>
        </div>
      </el-footer>
    </el-container>
  </div>
</template>

<script setup>
// 组件逻辑
</script>

<style>
/* 全局样式 */
body {
  margin: 0;
  padding: 0;
  font-family: 'Helvetica Neue', Helvetica, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', '微软雅黑', Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background-color: #f5f7fa;
}

.app-container {
  min-height: 100vh;
}

.el-header {
  background-color: #409EFF;
  color: white;
  display: flex;
  align-items: center;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.12);
}

.header-content {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
}

.el-main {
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;
  width: 100%;
}

.el-footer {
  background-color: #f5f7fa;
  color: #909399;
  text-align: center;
  border-top: 1px solid #e4e7ed;
}

.footer-content {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
}
</style>