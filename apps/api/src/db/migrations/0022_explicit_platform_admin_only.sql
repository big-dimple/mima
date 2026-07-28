CREATE OR REPLACE FUNCTION mima_is_platform_admin(candidate_user_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM system_role_assignments assignment
    WHERE assignment.user_id = candidate_user_id
      AND assignment.role = 'platform-admin'
  );
$$;
