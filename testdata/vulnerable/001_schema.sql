-- A multi-tenant billing schema, as a migration might leave it.
CREATE TABLE public.accounts (
    id bigint PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    api_token text
);

CREATE TABLE public.invoices (
    id bigint PRIMARY KEY,
    account_id bigint NOT NULL REFERENCES public.accounts(id),
    tenant_id uuid NOT NULL,
    total numeric(12,2) NOT NULL
);

CREATE POLICY tenant_isolation ON public.invoices
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;
