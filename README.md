# auth-service

Standalone identity service for DBIS tools (GRIPL, RAGulate, and future projects). Issues RS256-signed JWTs and exposes a JWKS endpoint so any consuming app can verify tokens locally without sharing a secret.

Design background: see the referenced discussion from [GRIPL-v2#32](https://github.com/DBIS-Legal-LLMs/GRIPL-v2/issues/32), [RAGulate_v2#121](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/121), [#122](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/122), [#123](https://github.com/DBIS-Legal-LLMs/RAGulate_v2/issues/123).

Integration documentation for consuming apps will land here once the core service and its first two real integrations (RAGulate, GRIPL) exist.
