# Sky Pivot Backend

> 零信任密码管理器（E2EE）后端服务

## 项目简介

Sky Pivot 是一款零信任架构的密码管理器，采用端到端加密（E2EE）设计，服务端对所有用户数据（密码、备注、密钥材料）进行**盲存储**——即在任何情况下都不执行加解密操作，不持有用户密钥或签名私钥。

### 核心设计原则

- **E2EE**: 主密码 → Argon2id/PBKDF2 → URK → AES-GCM(DEK) → AES-GCM(RK) → 字段级加密，全链路在客户端完成
- **零知识认证**: OPAQUE (Hofmann) 协议，服务端不接触用户密码
- **设备信任链**: Ed25519 设备密钥对，三级授权（扫码/中继双因素/恢复码）
- **Lamport 同步**: 逻辑时钟字段级冲突解决，增量同步
- **恢复码**: BIP39 12 词 + Challenge-Response 防重放

---

## 技术栈

| 层次 | 技术 | 版本 |
|------|------|------|
| **语言** | Java | 25 (LTS) |
| **框架** | Spring Boot | 4.1.0 |
| **构建** | Maven (多模块) | 3.9+ |
| **数据库** | MySQL | 8.0+ |
| **缓存** | Redis (Sentinel) | 7.x |
| **密钥管理** | HashiCorp Vault | 1.x |
| **数据库迁移** | Flyway | 11.5.0 |
| **认证协议** | OPAQUE (Hofmann) | 1.0.0 |
| **JWT** | jjwt | 0.12.6 |
| **加密原语** | Bouncy Castle、Ed25519 | 1.80 |
| **连接池** | HikariCP (DB) / Lettuce (Redis) | — |
| **虚拟线程** | JDK 25 Virtual Threads | — |
| **ORM** | Spring Data JPA + Hibernate | — |

---

## 工程结构

采用 8 模块 Maven 多模块架构：

```
sky-pivot/
├── pom.xml                         # 父 POM (BOM 依赖管理)
├── sky-pivot-common/               # 公共模块
├── sky-pivot-domain/               # 领域模型
├── sky-pivot-infrastructure/       # 基础设施
├── sky-pivot-application/          # 应用服务
├── sky-pivot-opaque/               # OPAQUE 认证
├── sky-pivot-api/                  # REST API 入口
└── sky-pivot-websocket/            # WebSocket 服务
```

### 模块说明

#### sky-pivot-parent（父 POM）

BOM 依赖管理，锁定所有外部依赖版本及子模块版本，提供 `pluginManagement` 统一配置 `maven-compiler-plugin` 和 `spring-boot-maven-plugin`。

#### sky-pivot-common

**用途**: 跨模块共享的基础组件，无业务逻辑依赖。

| 包 | 内容 |
|----|------|
| `common/` | `Constants` — 全局常量 |
| `dto/` | `ApiResponse<T>` — 统一 API 响应，含 `code`、`message`、`data`、`requestId`、`timestamp` |
| `exception/` | 11 个业务异常类（`CryptoException`、`TokenValidationException`、`WrongMasterPasswordException` 等） |

**依赖**: 仅 `jackson-databind`，零项目内模块依赖。

#### sky-pivot-domain

**用途**: 领域模型——JPA 实体、Spring Data Repository、领域枚举、领域事件。

| 包 | 内容 |
|----|------|
| `entity/` | `User`、`Password`、`SyncVersion`、`LoginHistory` |
| `repository/` | `UserRepository`、`PasswordRepository`、`SyncVersionRepository`、`LoginHistoryRepository` |

**依赖**: `sky-pivot-common`、`spring-boot-starter-data-jpa`

#### sky-pivot-infrastructure

**用途**: 基础设施层——数据库/Redis/Vault 客户端、安全拦截器、JWT 服务、定时任务、Flyway 迁移、Bouncy Castle 加密原语。

| 包 | 内容 |
|----|------|
| `config/properties/` | 6 个 `@ConfigurationProperties` 类（Crypto/JWT/LoginHistory/Security/Trash/WeChat） |
| `security/` | `JwtService`、`JwtAuthInterceptor`、`JwtAuthContext`、`RateLimitInterceptor`、`BiometricLockoutService` |
| `scheduler/` | `ScheduledTasks` — 定时清理回收站 |
| `db/migration/` | Flyway 迁移脚本（`V1__Initial_Schema.sql`） |

**依赖**: `sky-pivot-domain`、Spring Data Redis、Spring Cloud Vault、Caffeine、jjwt、Bouncy Castle、Flyway

#### sky-pivot-application

**用途**: 应用服务层——业务逻辑、DTO、业务异常处理。

| 包 | 内容 |
|----|------|
| `service/` | `CryptoService`（注意：**当前 MVPA 遗留，零信任模式下服务端不做加解密**）<br>`AuthService`、`HealthService`、`PasswordService`、`MasterPasswordService`、`SyncService`、`TrashService`、`UtilsService`、`WeChatService`、`AccountService` |
| `dto/` | 22 个请求/响应 DTO 记录类 |

**依赖**: `sky-pivot-domain`、`sky-pivot-infrastructure`

#### sky-pivot-opaque

**用途**: Hofmann OPAQUE 协议封装——注册、登录、密码更新流程中的客户端/服务端交互。

> **当前状态**: 占位模块，待 Phase 1.2 实现。

**依赖**: `sky-pivot-common`、`hofmann-springboot`

#### sky-pivot-api

**用途**: 应用程序入口——REST Controller、Filter、`@ControllerAdvice` 全局异常处理、Interceptor 注册。

| 包 | 内容 |
|----|------|
| — | `Application.java` — Spring Boot 启动类 |
| `controller/` | 9 个 Controller（Account/Password/Health/MasterPassword/MiniAppAuth/PcAuth/Sync/Trash/Utils） |
| `exception/` | `GlobalExceptionHandler` — 统一异常处理，返回 `{"code":"XXX","message":"...","requestId":"..."}` |
| `filter/` | `RequestIdFilter` — X-Request-ID 全链路透传（MDC + Response Header） |
| `config/` | `WebConfig` — 拦截器注册 |

**依赖**: `sky-pivot-application`、`sky-pivot-opaque`、`spring-boot-starter-web`、`spring-boot-starter-actuator`

#### sky-pivot-websocket

**用途**: WebSocket 服务——实时同步通知（`/ws/sync`）。

| 包 | 内容 |
|----|------|
| `config/` | `WebSocketConfig` — 端点注册、握手配置<br>`SyncWebSocketHandler` — 连接管理、按 userId 推送同步变更 |

**依赖**: `sky-pivot-application`、`spring-boot-starter-websocket`

---

## 部署运行

### 环境要求

- JDK 25
- Maven 3.9+
- MySQL 8.0+
- Redis 7.0+（可选，支持 Sentinel）
- HashiCorp Vault 1.x（可选，生产环境启用）

### 编译

```bash
cd sky-pivot
mvn clean package
```

编译产物位于 `sky-pivot-api/target/sky-pivot-api-1.0.0.jar`。

### 运行

```bash
# 开发环境（默认 profile=dev，H2 数据库）
java -jar sky-pivot-api/target/sky-pivot-api-1.0.0.jar

# 指定 profile
java -jar sky-pivot-api/target/sky-pivot-api-1.0.0.jar --spring.profiles.active=dev

# 生产环境（需设置环境变量）
export DATASOURCE_URL=jdbc:mysql://db-host:3306/sky_pivot
export DATASOURCE_USERNAME=sky_pivot
export DATASOURCE_PASSWORD=<your-db-password>
export REDIS_PASSWORD=<your-redis-password>
export VAULT_ROLE_ID=<vault-approle-role-id>
export VAULT_SECRET_ID=<vault-approle-secret-id>
export SPRING_PROFILES_ACTIVE=prod

java -jar sky-pivot-api/target/sky-pivot-api-1.0.0.jar
```

### Profile

| Profile | 数据库 | Vault | Flyway | 适用场景 |
|---------|--------|-------|--------|---------|
| `dev` | H2 (文件) | 关闭 | 可清理 | 本地开发 |
| `test` | H2 (内存) | 关闭 | 关闭 | 单元/集成测试 |
| `prod` | MySQL 8.0 | 启用 | 仅迁移 | 生产环境 |

默认 profile 为 `dev`，可通过 `SPRING_PROFILES_ACTIVE` 环境变量或 `--spring.profiles.active` 参数切换。

### 健康检查

应用启动后，访问 Actuator 端点：

```bash
# 健康检查（管理端口 8081，dev 模式下端口 8081）
curl http://localhost:8081/actuator/health

# 应用信息
curl http://localhost:8081/actuator/info
```

### 数据库初始化

Flyway 在应用启动时自动执行迁移。迁移脚本位于：

```
sky-pivot-infrastructure/src/main/resources/db/migration/
```

当前版本：`V1__Initial_Schema.sql`（users / passwords / sync_versions / login_history）

### WebSocket

同步端点：`ws://localhost:8080/ws/sync?token=<jwt-token>`

客户端通过 JWT Token 建立 WebSocket 连接，服务端按 userId 推送实时同步变更。

### 外部配置文件

应用启动时会尝试加载外部配置：

```
/usr/local/etc/sky-pivot/application.yml
```

使用 `optional:` 前缀，文件不存在时不影响启动。

### 关键环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SERVER_PORT` | 应用端口 | 8080 |
| `SPRING_PROFILES_ACTIVE` | 激活的 profile | dev |
| `DATASOURCE_URL` | 数据库连接 URL | jdbc:mysql://localhost:3306/sky_pivot |
| `DATASOURCE_USERNAME` | 数据库用户名 | sky_pivot |
| `DATASOURCE_PASSWORD` | 数据库密码 | （空） |
| `DATASOURCE_POOL_SIZE` | HikariCP 连接池上限 | 20 |
| `REDIS_HOST` | Redis 地址 | localhost |
| `REDIS_PORT` | Redis 端口 | 6379 |
| `REDIS_PASSWORD` | Redis 密码 | （空） |
| `VAULT_ENABLED` | 是否启用 Vault | false |
| `VAULT_HOST` | Vault 地址 | localhost |
| `VAULT_ROLE_ID` | Vault AppRole Role ID | （空） |
| `VAULT_SECRET_ID` | Vault AppRole Secret ID | （空） |
| `MANAGEMENT_PORT` | Actuator 管理端口 | 8081 |

---

## API 响应格式

所有 API 响应统一封装：

```json
{
  "code": "200",
  "message": "success",
  "data": {},
  "requestId": "a1b2c3d4e"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `code` | String | 状态码（"200" / "400" / "401" / "403" / "404" / "451" / "500" / "502"） |
| `message` | String | 可读的描述信息 |
| `data` | Object | 响应数据（成功时）或 null |
| `requestId` | String | 8 位 UUID，通过 `X-Request-ID` Header 全链路透传 |

---

## 安全约定

> ⚠️ 以下规则在代码审查和测试中强制执行：

1. **服务端禁止**执行 PBKDF2/Argon2id 派生用户密钥
2. **服务端禁止**AES 加解密用户数据（DEK/RK/字段）
3. **服务端禁止**存储主密码/URK/DEK/RK/恢复码明文
4. **服务端禁止**持有 AT（Access Token）签名私钥
5. 所有数据库变更通过 Flyway 迁移脚本
6. 所有敏感配置通过环境变量注入，禁止硬编码

---

## 许可证

MIT License. See `LICENSE` file for details.
