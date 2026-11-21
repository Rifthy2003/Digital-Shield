import { useAuth } from "@/context/AuthContext";
import { Card } from "@/components/Card";

export default function Profile() {
  const { user } = useAuth();
  if (!user) return null;

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <h1 className="text-2xl font-semibold">Profile &amp; Settings</h1>

      <Card className="space-y-3">
        <div>
          <p className="text-xs text-slate-500">Name</p>
          <p className="font-medium">{user.full_name ?? "—"}</p>
        </div>
        <div>
          <p className="text-xs text-slate-500">Email</p>
          <p className="font-medium">{user.email}</p>
        </div>
        <div>
          <p className="text-xs text-slate-500">Role</p>
          <p className="font-medium capitalize">{user.role}</p>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-500">Multi-factor authentication</p>
            <p className="font-medium">{user.mfa_enabled ? "Enabled" : "Not enabled"}</p>
          </div>
          {!user.mfa_enabled && (
            <span className="rounded-full bg-risk-medium/10 px-3 py-1 text-xs font-medium text-risk-medium">
              MFA setup coming soon
            </span>
          )}
        </div>
      </Card>

      <Card>
        <h2 className="mb-2 text-sm font-semibold text-slate-500">Data &amp; privacy</h2>
        <p className="text-sm text-slate-500">
          Account data export and deletion requests are planned for a future release. Contact support in
          the meantime for either request.
        </p>
      </Card>
    </div>
  );
}
