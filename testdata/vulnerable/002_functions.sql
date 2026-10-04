CREATE FUNCTION public.close_invoice(inv bigint) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
BEGIN
    UPDATE invoices SET total = 0 WHERE id = inv;
END;
$$;

CREATE FUNCTION public.run_report(sql text) RETURNS void
    LANGUAGE plpython3u
    AS $$ plpy.execute(sql) $$;

CREATE VIEW public.invoice_totals AS
    SELECT account_id, sum(total) AS total FROM public.accounts JOIN public.invoices ON true GROUP BY account_id;

CREATE EXTENSION dblink;
