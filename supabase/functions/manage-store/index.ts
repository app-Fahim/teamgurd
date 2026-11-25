import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "Method not allowed." });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) {
      return json(500, { error: "Server configuration is incomplete." });
    }

    const authorization = req.headers.get("Authorization") || "";
    const token = authorization.replace(/^Bearer\s+/i, "").trim();
    if (!token) return json(401, { error: "Authentication required." });

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    // Validate the caller's Supabase Auth access token before any privileged action.
    const { data: authData, error: authError } = await admin.auth.getUser(token);
    if (authError || !authData.user) return json(401, { error: "Invalid session." });

    const { data: platformAdmin, error: platformError } = await admin
      .from("teamguard_platform_admins")
      .select("user_id")
      .eq("user_id", authData.user.id)
      .maybeSingle();

    if (platformError) throw platformError;
    if (!platformAdmin) return json(403, { error: "Super Admin access required." });

    const body = await req.json().catch(() => ({}));
    const action = String(body?.action || "");

    if (action === "list") {
      const { data: workspaces, error: workspaceError } = await admin
        .from("teamguard_workspaces")
        .select("id,name,created_at")
        .order("created_at", { ascending: false });
      if (workspaceError) throw workspaceError;

      const { data: managers, error: managerError } = await admin
        .from("teamguard_members")
        .select("workspace_id,user_id,username,full_name,role")
        .eq("role", "manager");
      if (managerError) throw managerError;

      const managerByWorkspace = new Map(
        (managers || []).map((m) => [m.workspace_id, {
          user_id: m.user_id,
          username: m.username,
          full_name: m.full_name,
        }]),
      );

      return json(200, {
        stores: (workspaces || []).map((w) => ({
          id: w.id,
          name: w.name,
          created_at: w.created_at,
          manager: managerByWorkspace.get(w.id) || null,
        })),
      });
    }

    if (action === "reports") {
      const workspaceId = String(body?.workspaceId || "").trim();
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)) {
        return json(400, { error: "A valid Store ID is required." });
      }

      const { data: workspace, error: workspaceError } = await admin
        .from("teamguard_workspaces")
        .select("id,name")
        .eq("id", workspaceId)
        .maybeSingle();
      if (workspaceError) throw workspaceError;
      if (!workspace) return json(404, { error: "Store not found." });

      const [{ data: reports, error: reportsError }, { data: members, error: membersError }, { data: shared, error: sharedError }] = await Promise.all([
        admin.from("teamguard_reports")
          .select("id,workspace_id,submitted_by,report_data,created_at")
          .eq("workspace_id", workspaceId)
          .order("created_at", { ascending: false })
          .limit(1000),
        admin.from("teamguard_members")
          .select("user_id,full_name,username,role")
          .eq("workspace_id", workspaceId),
        admin.from("teamguard_app_data")
          .select("data")
          .eq("workspace_id", workspaceId)
          .maybeSingle(),
      ]);
      if (reportsError) throw reportsError;
      if (membersError) throw membersError;
      if (sharedError) throw sharedError;

      const memberById = new Map((members || []).map((m) => [m.user_id, {
        name: m.full_name || m.username || "—",
        role: m.role,
      }]));
      const pickers = Array.isArray(shared?.data?.pickers) ? shared.data.pickers : [];
      const pickerById = new Map(pickers.map((p) => [String(p.id), {
        name: p.name || p.pickerName || "—",
        line: p.line || "—",
      }]));

      return json(200, {
        store: workspace,
        reports: (reports || []).map((row) => {
          const report = row.report_data && typeof row.report_data === "object" ? row.report_data : {};
          const leader = memberById.get(row.submitted_by) || {};
          const picker = pickerById.get(String(report.pickerId)) || {};
          return {
            id: row.id,
            date: report.date || row.created_at,
            shift: report.shift || "—",
            created_at: row.created_at,
            leader_name: leader.name || "—",
            picker_name: picker.name || "—",
            picker_line: picker.line || "—",
            report_data: report,
          };
        }),
      });
    }

    if (action !== "create") return json(400, { error: "Unsupported action." });

    const storeName = String(body?.storeName || "").trim();
    const managerName = String(body?.managerName || "").trim();
    const managerEmail = String(body?.managerEmail || "").trim().toLowerCase();
    const managerUsername = String(body?.managerUsername || "").trim();
    const managerPassword = String(body?.managerPassword || "");

    if (!storeName || !managerName || !managerEmail || !managerUsername || !managerPassword) {
      return json(400, { error: "Store name and all Manager account fields are required." });
    }
    if (storeName.length > 120 || managerName.length > 120 || managerUsername.length > 60) {
      return json(400, { error: "One or more fields are too long." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(managerEmail)) {
      return json(400, { error: "Enter a valid Manager email address." });
    }
    if (managerPassword.length < 8) {
      return json(400, { error: "Manager password must be at least 8 characters." });
    }

    const { data: workspace, error: createWorkspaceError } = await admin
      .from("teamguard_workspaces")
      .insert({ name: storeName })
      .select("id,name,created_at")
      .single();
    if (createWorkspaceError) throw createWorkspaceError;

    let createdUserId: string | null = null;
    try {
      const { data: userResult, error: createUserError } = await admin.auth.admin.createUser({
        email: managerEmail,
        password: managerPassword,
        email_confirm: true,
        user_metadata: { full_name: managerName },
      });
      if (createUserError) throw createUserError;
      createdUserId = userResult.user.id;

      const { error: memberError } = await admin.from("teamguard_members").insert({
        workspace_id: workspace.id,
        user_id: createdUserId,
        username: managerUsername,
        role: "manager",
        full_name: managerName,
        shift: "Both",
      });
      if (memberError) throw memberError;

      // Create the shared-data row expected by the existing Manager login flow.
      const { error: appDataError } = await admin.from("teamguard_app_data").insert({
        workspace_id: workspace.id,
        data: {},
      });
      if (appDataError) throw appDataError;
    } catch (creationError) {
      if (createdUserId) await admin.auth.admin.deleteUser(createdUserId);
      await admin.from("teamguard_workspaces").delete().eq("id", workspace.id);
      throw creationError;
    }

    return json(200, {
      success: true,
      store: { id: workspace.id, name: workspace.name, created_at: workspace.created_at },
      manager: { user_id: createdUserId, name: managerName, username: managerUsername, email: managerEmail },
    });
  } catch (error) {
    console.error("manage-store error:", error);
    return json(400, { error: error instanceof Error ? error.message : "Request failed." });
  }
});