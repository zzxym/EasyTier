# SDWAN Uptime Monitor

一个用于监控 SDWAN 实例健康状态和运行时间的系统。

## 功能特性

- 🏥 **健康监控**: 实时监控 SDWAN 节点的健康状态
- 📊 **数据统计**: 提供详细的运行时间和响应时间统计
- 🔧 **实例管理**: 管理多个 SDWAN 实例
- 🌐 **Web界面**: 直观的 Web 管理界面
- 🚨 **告警系统**: 支持健康状态异常告警
- 📈 **图表展示**: 可视化展示监控数据

## 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Database      │
│   (Vue.js)      │◄──►│   (Rust/Axum)   │◄──►│   (SQLite)      │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Dashboard   │ │    │ │ API Routes  │ │    │ │ Nodes       │ │
│ │ Health View │ │    │ │ Health      │ │    │ │ Health      │ │
│ │ Node Mgmt   │ │    │ │ Instances   │ │    │ │ Instances   │ │
│ │ Charts      │ │    │ │ Scheduler   │ │    │ │ Stats       │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 快速开始

### 环境要求

- **Rust**: 1.70+
- **Node.js**: 16+
- **npm**: 8+

### 开发环境

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd easytier-uptime
   ```

2. **启动开发环境**
   ```bash
   ./start-dev.sh
   ```