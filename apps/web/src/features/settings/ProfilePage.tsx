// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, KeyRound, Upload } from "lucide-react";
import { useSession } from "../../lib/session";
import { Avatar, Button, Card, Input, Mono } from "../../components/ui";

/**
 * /me profile editor (humans only). Machines get RESOURCE_NOT_FOUND from
 * GET /v1/me/profile; the page then shows facts only and hides the editing
 * affordances instead of failing.
 */

const MAX_IMAGE_BYTES = 100 * 1024;

/** Downscale + re-encode a picked file until the data URL fits ≤100KB. */
async function fileToDataUrl(file: File): Promise<string> {
  const bitmap = await createImageBitmap(file);
  // Avatars render at ≤48px; 256px keeps them crisp on high-DPI displays.
  let edge = Math.min(256, Math.max(bitmap.width, bitmap.height));
  for (;;) {
    const scale = edge / Math.max(bitmap.width, bitmap.height);
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("canvas unavailable");
    ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    const url = canvas.toDataURL("image/jpeg", 0.85);
    // Data-URL length ≈ bytes × 4/3; compare on the encoded string itself.
    if (url.length <= MAX_IMAGE_BYTES || edge <= 32) {
      if (url.length > MAX_IMAGE_BYTES) throw new Error("image cannot be compressed under 100KB");
      return url;
    }
    edge = Math.floor(edge / 2);
  }
}

export function ProfilePage() {
  const { api, identityId } = useSession();
  const qc = useQueryClient();
  const profile = useQuery({
    queryKey: ["me-profile"],
    queryFn: () => api.getMyProfile(),
    retry: false,
  });
  // Machine identities (404) simply have no profile to edit.
  const isMachine = profile.isError;

  const [name, setName] = useState("");
  const [image, setImage] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (profile.data && !dirty) {
      setName(profile.data.name);
      setImage(profile.data.image);
    }
  }, [profile.data, dirty]);

  const save = useMutation({
    mutationFn: () => {
      setError("");
      return api.updateMyProfile({ name, image });
    },
    onSuccess: (updated) => {
      qc.setQueryData(["me-profile"], updated);
      setDirty(false);
    },
    onError: (err) => setError(String(err)),
  });

  const pickFile = async (file: File | undefined) => {
    if (!file) return;
    setError("");
    try {
      setImage(await fileToDataUrl(file));
      setDirty(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const displayName = dirty ? name : (profile.data?.name ?? identityId ?? "");

  return (
    <main className="p-6 max-w-3xl mx-auto space-y-4">
      <Link to="/" className="text-muted hover:text-fg inline-flex items-center gap-1 text-sm no-underline">
        <ArrowLeft size={14} /> Back to dashboard
      </Link>
      <h1 className="text-lg font-semibold">Profile</h1>

      <Card data-testid="profile-card" className="space-y-4">
        <div className="flex items-center gap-4">
          <Avatar name={displayName || "?"} image={dirty ? image : (profile.data?.image ?? null)} size="lg" />
          <div className="min-w-0">
            <p className="font-medium truncate">{displayName || "—"}</p>
            {profile.data?.email && <p className="text-sm text-muted truncate">{profile.data.email}</p>}
            <p className="text-xs text-muted truncate" title={identityId ?? ""}>
              <Mono>{identityId}</Mono>
            </p>
          </div>
        </div>

        {profile.isLoading && <p className="text-sm text-muted">Loading…</p>}
        {isMachine && (
          <p className="text-sm text-muted" data-testid="profile-unavailable">
            This identity has no editable profile.
          </p>
        )}

        {profile.data && (
          <form
            className="space-y-3 text-sm"
            onSubmit={(e) => {
              e.preventDefault();
              if (name.trim()) save.mutate();
            }}
          >
            <div className="flex flex-wrap items-center gap-2">
              <label className="text-muted w-28" htmlFor="profile-name">Display name</label>
              <Input
                id="profile-name"
                data-testid="profile-name"
                className="w-72"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  setDirty(true);
                }}
              />
            </div>
            <div className="flex flex-wrap items-start gap-2">
              <label className="text-muted w-28 pt-1.5" htmlFor="profile-image-url">Avatar</label>
              <div className="space-y-2">
                <Input
                  id="profile-image-url"
                  data-testid="profile-image-url"
                  className="w-96"
                  placeholder="https://… image URL (or upload below)"
                  value={image && !image.startsWith("data:") ? image : ""}
                  onChange={(e) => {
                    setImage(e.target.value || null);
                    setDirty(true);
                  }}
                />
                <div className="flex items-center gap-2">
                  <Button type="button" variant="ghost" onClick={() => fileRef.current?.click()}>
                    <Upload size={13} className="inline mr-1" /> Upload image…
                  </Button>
                  {image?.startsWith("data:") && (
                    <span className="text-xs text-muted">uploaded image set</span>
                  )}
                  {image && (
                    <Button
                      type="button"
                      variant="ghost"
                      onClick={() => {
                        setImage(null);
                        setDirty(true);
                      }}
                    >
                      Remove
                    </Button>
                  )}
                  <input
                    ref={fileRef}
                    type="file"
                    accept="image/*"
                    className="hidden"
                    data-testid="profile-image-file"
                    onChange={(e) => void pickFile(e.target.files?.[0])}
                  />
                </div>
                <p className="text-xs text-muted">
                  Uploads are downscaled in your browser and stored inline (≤100KB); nothing is
                  fetched server-side.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button type="submit" data-testid="profile-save" disabled={!dirty || !name.trim() || save.isPending}>
                Save profile
              </Button>
              {save.isSuccess && !dirty && <span className="text-xs text-allow">Saved.</span>}
            </div>
            {error && <p className="text-deny">{error}</p>}
          </form>
        )}
      </Card>

      <Card>
        <p className="text-sm">
          <KeyRound size={14} className="inline mr-1.5 text-muted" />
          Passkeys and CLI credentials live on{" "}
          <Link to="/credentials">My credentials</Link>.
        </p>
      </Card>
    </main>
  );
}
