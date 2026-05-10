# 前端界面 (frontend-gui)

前端基于 React 18 + Ant Design 6 + Vite 6 构建，提供事件查询、告警管理、仪表盘、实时监控等 UI 功能。

## 目录

- [文件结构](#文件结构)
- [技术栈](#技术栈)
- [项目结构](#项目结构)
- [路由配置](#路由配置)
- [API 代理配置](#api-代理配置)
- [核心组件](#核心组件)

## 文件结构

| 文件/目录 | 说明 |
|-----------|------|
| `frontend-gui/package.json` | 前端依赖和脚本 |
| `frontend-gui/vite.config.ts` | Vite 配置、API 代理 |
| `frontend-gui/tsconfig.json` | TypeScript 配置 |
| `frontend-gui/src/App.tsx` | 应用入口、路由 |
| `frontend-gui/src/main.tsx` | React 挂载点 |
| `frontend-gui/src/components/` | 可复用组件 |
| `frontend-gui/src/pages/` | 页面组件 |
| `frontend-gui/src/services/` | API 调用服务 |
| `frontend-gui/src/hooks/` | 自定义 Hooks |
| `frontend-gui/src/types/` | TypeScript 类型定义 |
| `frontend-gui/index.html` | 入口 HTML |

## 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| React | 18.3.x | UI 框架 |
| React Router | 6.30.x | 路由管理 |
| Ant Design | 6.1.x | UI 组件库 |
| Vite | 6.4.x | 构建工具 |
| TypeScript | 5.x | 类型安全 |
| Axios | 1.x | HTTP 客户端 |
| dayjs | 1.11.x | 日期处理 |
| echarts | 6.0.x | 图表可视化 |
| react-syntax-highlighter | 15.6.x | 代码高亮 |

### package.json 脚本

```json
{
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview"
  }
}
```

### 关键依赖

```json
{
  "dependencies": {
    "antd": "^6.1.0",
    "axios": "^1.13.5",
    "dayjs": "^1.11.19",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.30.1",
    "echarts": "^6.0.0",
    "react-syntax-highlighter": "^15.6.6"
  },
  "devDependencies": {
    "@types/react": "^18.3.27",
    "@types/react-dom": "^18.3.7",
    "@vitejs/plugin-react": "^4.7.0",
    "typescript": "~5.8.3",
    "vite": "^6.4.1"
  }
}
```

## 项目结构

```
frontend-gui/
├── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
├── public/
│   └── favicon.svg
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── components/
    │   ├── Layout/
    │   │   └── MainLayout.tsx
    │   ├── EventTable/
    │   │   ├── index.tsx
    │   │   └── EventDetailModal.tsx
    │   ├── AlertList/
    │   │   ├── index.tsx
    │   │   └── AlertDetailModal.tsx
    │   └── Dashboard/
    │       ├── OverviewCard.tsx
    │       └── MITREMatrix.tsx
    ├── pages/
    │   ├── Events.tsx
    │   ├── Alerts.tsx
    │   ├── Dashboard.tsx
    │   ├── Import.tsx
    │   ├── Live.tsx
    │   └── Rules.tsx
    ├── services/
    │   ├── api.ts
    │   ├── events.ts
    │   ├── alerts.ts
    │   └── import.ts
    ├── hooks/
    │   ├── useSSE.ts
    │   └── usePagination.ts
    └── types/
        ├── event.ts
        ├── alert.ts
        └── api.ts
```

## 路由配置

```tsx
// App.tsx
function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<MainLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="events" element={<Events />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="import" element={<Import />} />
          <Route path="live" element={<Live />} />
          <Route path="rules" element={<Rules />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
```

### 路由页面

| 路径 | 页面 | 功能 |
|------|------|------|
| `/` | Dashboard | 仪表盘：事件总数、告警统计、MITRE 矩阵 |
| `/events` | Events | 事件列表：搜索、过滤、分页、详情弹窗 |
| `/alerts` | Alerts | 告警列表：状态筛选、解决、误报标记 |
| `/import` | Import | 文件导入：拖拽上传、进度条、历史 |
| `/live` | Live | 实时监控：SSE 事件流 |
| `/rules` | Rules | 规则管理：启用/禁用、状态查看 |

## API 代理配置

前端开发服务器通过 Vite 代理将 `/api` 请求转发到后端：

```typescript
// vite.config.ts
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:18437',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://localhost:18437',
        changeOrigin: true,
      },
    },
  },
});
```

### Axios 实例

```typescript
// services/api.ts
const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.response.use(
  (response) => response.data,
  (error) => {
    message.error(error.response?.data?.error || 'Request failed');
    return Promise.reject(error);
  }
);
```

## 核心组件

### 事件列表组件 (EventTable)

```tsx
interface EventTableProps {
  searchParams: SearchParams;
  onSelect: (event: Event) => void;
}

const EventTable: React.FC<EventTableProps> = ({ searchParams, onSelect }) => {
  const [data, setData] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  const fetchData = async (page: number, pageSize: number) => {
    setLoading(true);
    try {
      const res = await eventsAPI.list({ ...searchParams, page, pageSize });
      setData(res.events);
      setTotal(res.total);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Table
      dataSource={data}
      loading={loading}
      rowKey="id"
      columns={columns}
      onChange={(pagination) => fetchData(pagination.current!, pagination.pageSize!)}
      pagination={{ total, showSizeChanger: true }}
    />
  );
};
```

### 实时监控组件 (LiveView)

使用 SSE 接收实时事件流：

```tsx
const LiveView: React.FC = () => {
  const [events, setEvents] = useState<LiveEvent[]>([]);

  useEffect(() => {
    const evtSource = new EventSource('/api/live');

    evtSource.onmessage = (e) => {
      const event = JSON.parse(e.data);
      setEvents((prev) => [event, ...prev].slice(0, 100));
    };

    return () => evtSource.close();
  }, []);

  return (
    <List
      dataSource={events}
      renderItem={(item) => (
        <List.Item>
          <Tag color={getSeverityColor(item.severity)}>{item.severity}</Tag>
          <Text>{item.message}</Text>
          <Text type="secondary">{dayjs(item.timestamp).format('HH:mm:ss')}</Text>
        </List.Item>
      )}
    />
  );
};
```

### 仪表盘组件 (Dashboard)

```tsx
const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    dashboardAPI.overview().then(setStats);
  }, []);

  return (
    <Row gutter={[16, 16]}>
      <Col span={6}>
        <Card title="总事件数" bordered={false}>
          <Statistic value={stats?.totalEvents} />
        </Card>
      </Col>
      <Col span={6}>
        <Card title="总告警数" bordered={false}>
          <Statistic value={stats?.totalAlerts} valueStyle={{ color: '#cf1322' }} />
        </Card>
      </Col>
      <Col span={6}>
        <Card title="未解决告警" bordered={false}>
          <Statistic value={stats?.unresolvedAlerts} valueStyle={{ color: '#faad14' }} />
        </Card>
      </Col>
      <Col span={6}>
        <Card title="导入文件数" bordered={false}>
          <Statistic value={stats?.importFiles} />
        </Card>
      </Col>
      <Col span={24}>
        <Card title="MITRE ATT&CK 矩阵">
          <MITREMatrix data={stats?.mitreData} />
        </Card>
      </Col>
    </Row>
  );
};
```
