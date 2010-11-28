{application, gen_icmp,
    [
    {description, "Generate ICMP packets"},
    {vsn, "0.01"},
    {modules, [
        gen_icmp
            ]},
    {registered, []},
    {applications, [
        kernel,
        stdlib
            ]},
    {env, []}
    ]}.

