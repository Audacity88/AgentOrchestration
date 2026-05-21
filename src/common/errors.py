"""Custom exception definitions."""


class AgentOrchestratorError(Exception):
    """Base exception for all platform errors."""
    pass


class AgentNotFoundError(AgentOrchestratorError):
    def __init__(self, agent_id: str):
        super().__init__(f"Agent not found: {agent_id}")


class AgentTimeoutError(AgentOrchestratorError):
    def __init__(self, agent_id: str, timeout: int):
        super().__init__(f"Agent {agent_id} timed out after {timeout}s")


class TaskExecutionError(AgentOrchestratorError):
    def __init__(self, task_id: str, reason: str):
        super().__init__(f"Task {task_id} failed: {reason}")


class ConfigurationError(AgentOrchestratorError):
    def __init__(self, message: str):
        super().__init__(f"Configuration error: {message}")


class AuthenticationError(AgentOrchestratorError):
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message)


class RateLimitError(AgentOrchestratorError):
    def __init__(self, retry_after: int = 60):
        super().__init__(f"Rate limit exceeded. Retry after {retry_after}s")
        self.retry_after = retry_after


class ResourceExhaustedError(AgentOrchestratorError):
    def __init__(self, resource: str):
        super().__init__(f"Resource exhausted: {resource}")


class ArtifactManifestError(AgentOrchestratorError):
    def __init__(self, message: str):
        super().__init__(f"Artifact manifest error: {message}")


class ArtifactIntegrityError(AgentOrchestratorError):
    def __init__(self, message: str):
        super().__init__(f"Artifact integrity failure: {message}")

# 2019-01-25T13:21:06 update

# 2019-02-15T19:31:32 update

# 2019-03-18T12:12:35 update

# 2019-04-29T20:33:13 update

# 2019-05-13T10:17:52 update

# 2019-08-08T11:13:54 update

# 2019-10-03T13:18:53 update

# 2019-12-25T12:36:57 update

# 2020-01-08T20:51:36 update

# 2020-02-04T16:32:04 update

# 2020-02-14T20:25:19 update

# 2020-05-13T17:33:02 update

# 2020-05-21T08:58:23 update

# 2020-06-17T19:16:10 update

# 2020-06-29T08:36:22 update

# 2020-09-15T17:03:38 update

# 2021-07-29T17:26:45 update

# 2021-09-09T14:13:15 update

# 2021-09-29T15:38:28 update

# 2021-10-26T11:39:45 update

# 2021-10-29T15:26:37 update

# 2021-11-11T16:23:02 update

# 2021-11-18T10:30:52 update

# 2022-01-14T15:33:56 update

# 2022-01-31T08:19:36 update

# 2022-04-07T17:47:40 update

# 2022-04-18T17:38:06 update

# 2022-05-24T11:23:57 update

# 2022-09-27T10:19:23 update

# 2022-09-30T13:09:07 update

# 2022-10-17T10:55:10 update

# 2022-10-26T09:50:18 update

# 2022-11-03T09:36:54 update

# 2022-11-10T09:07:03 update

# 2022-11-16T08:08:03 update

# 2022-11-28T20:47:55 update

# 2023-04-28T20:42:41 update

# 2023-06-07T17:10:04 update

# 2023-09-26T10:17:12 update

# 2023-10-26T09:47:24 update

# 2023-11-14T11:44:13 update

# 2023-11-29T15:19:51 update

# 2023-12-25T15:39:17 update

# 2024-04-30T08:47:44 update

# 2024-05-22T13:29:35 update

# 2024-06-28T19:57:27 update

# 2024-07-02T17:47:50 update

# 2024-08-19T17:30:45 update

# 2024-11-05T13:23:33 update

# 2024-11-15T13:45:56 update

# 2024-12-18T13:22:39 update

# 2025-01-06T18:00:02 update

# 2025-01-12T08:42:22 update

# 2025-03-07T18:18:34 update

# 2025-06-09T15:05:33 update

# 2025-06-09T14:45:48 update

# 2025-06-11T08:33:42 update

# 2025-07-23T19:14:32 update

# 2025-08-20T12:30:58 update

# 2025-10-16T12:55:17 update

# 2025-12-18T11:03:19 update

# 2026-05-04T18:36:18 update

# 2026-05-11T11:46:37 update
