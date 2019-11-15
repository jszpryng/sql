/* User/Group Permissions */
WITH UGP as (
    SELECT 
        N.authorizable_type AS "Object Type"
        , N.grantee_id AS "Is _users.id/groups.id"
        , N.grantee_type AS "Is User/Group"
        , N.capability_id, S.name AS "Site"
        , S.id AS "site_id"
        , CASE
            WHEN N.permission = 1 THEN 'Grant'
            WHEN N.permission = 2 THEN 'Deny'
            WHEN N.permission = 3 THEN 'Grant'
            WHEN N.permission = 4 THEN 'Deny'
            ELSE NULL
        END AS "Base Authorization"
        , U.name as UID
        , U.friendly_name as "Friendly Name"
        , P.name as "Object Name"
        , P.name as "Project"
        , NULL as "Workbook"
        , NULL as "View"
    FROM 
        next_gen_permissions N
    LEFT JOIN 
        _users U 
            ON N.grantee_id = U.id
    LEFT JOIN 
        sites S 
            ON U.site_id = S.id
    LEFT JOIN 
        projects P 
            ON N.authorizable_id = P.id
    WHERE 
        N.grantee_type = 'User' 
        AND N.authorizable_type = 'Project' 
        AND P.name is not NULL --user project permissions
    UNION
    SELECT 
        N.authorizable_type AS "Object Type"
        , N.grantee_id AS "Is _users.id/groups.id"
        , N.grantee_type AS "Is User/Group"
        , N.capability_id
        , S.name AS "Site"
        , S.id AS "site_id"
        , CASE
            WHEN N.permission = 1 THEN 'Grant'
            WHEN N.permission = 2 THEN 'Deny'
            WHEN N.permission = 3 THEN 'Grant'
            WHEN N.permission = 4 THEN 'Deny'
            ELSE NULL
        END AS "Base Authorization"
    , G.name as UID
    , G.name as "Friendly Name"
    , P.name as "Object Name"
    , P.name as "Project"
    , NULL as "Workbook"
    , NULL as "View"
    FROM 
        next_gen_permissions N
    LEFT JOIN 
        groups G 
            ON N.grantee_id = G.id
    LEFT JOIN 
        sites S 
            ON G.site_id = S.id
    LEFT JOIN 
        projects P 
            ON N.authorizable_id = P.id
    WHERE 
        N.grantee_type = 'Group' 
        AND N.authorizable_type = 'Project' 
        AND P.name is not NULL -- group project permissions
    UNION
    SELECT N.authorizable_type AS "Object Type", N.grantee_id AS "Is _users.id/groups.id", N.grantee_type AS "Is User/Group", N.capability_id, S.name AS "Site", S.id AS "site_id",
    CASE
    WHEN N.permission = 1 THEN 'Grant'
    WHEN N.permission = 2 THEN 'Deny'
    WHEN N.permission = 3 THEN 'Grant'
    WHEN N.permission = 4 THEN 'Deny'
    ELSE NULL
    END AS "Base Authorization",
    G.name as UID, G.name as "Friendly Name", W.name as "Object Name", P.name as "Project", W.name as "Workbook", NULL as "View"
    FROM next_gen_permissions N
    LEFT JOIN groups G ON N.grantee_id = G.id
    LEFT JOIN sites S ON G.site_id = S.id
    LEFT JOIN workbooks W ON N.authorizable_id = W.id
    LEFT JOIN projects P ON W.project_id = P.id
    WHERE N.grantee_type = 'Group' AND N.authorizable_type = 'Workbook' AND P.name is not NULL -- group workbooks permissions
    UNION
    SELECT N.authorizable_type AS "Object Type", N.grantee_id AS "Is _users.id/groups.id", N.grantee_type AS "Is User/Group", N.capability_id, S.name AS "Site", S.id AS "site_id",
    CASE
    WHEN N.permission = 1 THEN 'Grant'
    WHEN N.permission = 2 THEN 'Deny'
    WHEN N.permission = 3 THEN 'Grant'
    WHEN N.permission = 4 THEN 'Deny'
    ELSE NULL
    END AS "Base Authorization",
    U.name as UID, U.friendly_name as "Friendly Name", W.name as "Object Name", P.name as "Project", W.name as "Workbook", NULL as "View"
    FROM next_gen_permissions N
    LEFT JOIN _users U ON N.grantee_id = U.id
    LEFT JOIN sites S ON U.site_id = S.id
    LEFT JOIN workbooks W ON N.authorizable_id = W.id
    LEFT JOIN projects P ON W.project_id = P.id
    WHERE N.grantee_type = 'User' AND N.authorizable_type = 'Workbook' AND P.name is not NULL -- user workbooks permissions
    UNION
    SELECT N.authorizable_type AS "Object Type", N.grantee_id AS "Is _users.id/groups.id", N.grantee_type AS "Is User/Group", N.capability_id, S.name AS "Site", S.id AS "site_id",
    CASE
    WHEN N.permission = 1 THEN 'Grant'
    WHEN N.permission = 2 THEN 'Deny'
    WHEN N.permission = 3 THEN 'Grant'
    WHEN N.permission = 4 THEN 'Deny'
    ELSE NULL
    END AS "Base Authorization",
    G.name as UID, G.name as "Friendly Name", V.name as "Object Name", P.name as "Project", W.name as "Workbook", V.name as "View"
    FROM next_gen_permissions N
    LEFT JOIN groups G ON N.grantee_id = G.id
    LEFT JOIN sites S ON G.site_id = S.id
    LEFT JOIN views V ON N.authorizable_id = V.id
    LEFT JOIN workbooks W ON V.workbook_id = W.id
    LEFT JOIN projects P ON W.project_id = P.id
    WHERE N.grantee_type = 'Group' AND N.authorizable_type = 'View' AND P.name is not NULL -- group view permissions
    UNION
    SELECT N.authorizable_type AS "Object Type", N.grantee_id AS "Is _users.id/groups.id", N.grantee_type AS "Is User/Group", N.capability_id, S.name AS "Site", S.id AS "site_id",
    CASE
    WHEN N.permission = 1 THEN 'Grant'
    WHEN N.permission = 2 THEN 'Deny'
    WHEN N.permission = 3 THEN 'Grant'
    WHEN N.permission = 4 THEN 'Deny' ELSE NULL
    END AS "Base Authorization",
    U.name as UID, U.friendly_name as "Friendly Name", V.name as "Object Name", P.name as "Project", W.name as "Workbook", V.name as "View"
    FROM next_gen_permissions N
    LEFT JOIN _users U ON N.grantee_id = U.id
    LEFT JOIN sites S ON U.site_id = S.id
    LEFT JOIN views V ON N.authorizable_id = V.id
    LEFT JOIN workbooks W ON V.workbook_id = W.id
    LEFT JOIN projects P ON W.project_id = P.id
    WHERE N.grantee_type = 'User' AND N.authorizable_type = 'Workbook' AND P.name is not NULL -- user workbooks permissions
    )

    select UGP.uid, UGP."Friendly Name", UGP."Is _users.id/groups.id", UGP."Is User/Group", UGP."Site", UGP."Workbook", UGP."Project", UGP."View",
    UGP."Base Authorization", ALP."Is SysAdmin", ALP."Is SiteAdmin"
    from (
    /* Admin Level Permissions (10 = Sys, 5 = Site) */
    SELECT system_users.name AS user_name, system_users.id AS system_user_id, users.id AS user_id, sites.id AS site_id,
    CASE
    WHEN system_users.admin_level = 10 THEN 1
    ELSE 0
    END AS "Is SysAdmin",
    CASE
    WHEN system_users.admin_level = 5 THEN 1
    ELSE 0
    END AS "Is SiteAdmin"
    FROM system_users
    join users on users.system_user_id = system_users.id
    join sites on users.site_id = sites.id
)ALP
JOIN UGP
on UGP.uid= ALP."user_name"
