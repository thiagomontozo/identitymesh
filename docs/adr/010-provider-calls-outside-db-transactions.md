# ADR 010: Provider calls outside database transactions

Status: Accepted

PostgreSQL and providers share no transaction manager. Local intent commits first, remote work runs without a long DB transaction, and result/observation persists in new transactions.
