CREATE TABLE public.invoices (
    id bigint PRIMARY KEY,
    tenant_id uuid NOT NULL,
    total numeric(12,2) NOT NULL,
    note text
);

ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON public.invoices
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

CREATE FUNCTION public.close_invoice(inv bigint) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
BEGIN
    UPDATE public.invoices SET total = 0 WHERE id = inv;
END;
$$;

REVOKE ALL ON FUNCTION public.close_invoice(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.close_invoice(bigint) TO app_user;

CREATE VIEW public.invoice_totals WITH (security_invoker = true) AS
    SELECT tenant_id, sum(total) AS total FROM public.invoices GROUP BY tenant_id;

CREATE ROLE app_user WITH LOGIN NOSUPERUSER NOCREATEROLE;
