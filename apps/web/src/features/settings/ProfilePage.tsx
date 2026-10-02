// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ImagePlus, Lock, Trash2 } from "lucide-react";
import { useSession } from "../../lib/session";
import { displayEmail } from "../../lib/identity";
import { chooseThemePreference, themePreference, type ThemePreference } from "../../lib/theme";
import { Avatar, Button, Input, Kbd, SectionCard, Segmented, cn } from "../../components/ui";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";

/**
 * Profile (humans only). Machines get RESOURCE_NOT_FOUND from
 * GET /v1/me/profile; the page then says so instead of failing.
 */

const MAX_IMAGE_BYTES = 100 * 1024;

/** Downscale and re-encode a picked file until the data URL fits in 100KB. */
async function fileToDataUrl(file: File): Promise<string> {
  const bitmap = await createImageBitmap(file);
  // Avatars render at up to 64px; 256px keeps them crisp on high-DPI displays.
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
    // Data-URL length is about bytes × 4/3; compare on the encoded string itself.
    if (url.length <= MAX_IMAGE_BYTES || edge <= 32) {
      if (url.length > MAX_IMAGE_BYTES) throw new Error("This image cannot be compressed under 100KB.");
      return url;
    }
    edge = Math.floor(edge / 2);
  }
}

export function ProfilePage() {
  const { api, identityId } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const profile = useQuery({ queryKey: ["me-profile"], queryFn: () => api.getMyProfile(), retry: false });
  const [name, setName] = useState("");
  const [image, setImage] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (profile.data && !dirty) {
      setName(profile.data.name);
      setImage(profile.data.image);
    }
  }, [profile.data, dirty]);

  const save = useMutation({
    mutationFn: () => api.updateMyProfile({ name: name.trim(), image }),
    onSuccess: (updated) => {
      qc.setQueryData(["me-profile"], updated);
      setDirty(false);
      toast.success("Profile saved");
    },
    onError: (err) => setError(errorMessage(err)),
  });
  const pickFile = async (file: File | undefined) => {
    if (!file) return;
    setError("");
    try {
      setImage(await fileToDataUrl(file));
      setDirty(true);
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  if (profile.isError) {
    return (
      <SectionCard title="Profile" data-testid="profile-unavailable">
        <p className="px-5 py-4 text-[13px] text-muted">
          This identity ({identityId}) is a machine and has no editable profile. Its credentials are managed under Access.
        </p>
      </SectionCard>
    );
  }
  const email = displayEmail(profile.data?.email);
  return (
    <div className="space-y-6">
      <SectionCard title="Profile" description="How you appear to others in this installation." data-testid="profile-card">
        <form
          className="divide-y divide-bd"
          onSubmit={(e) => {
            e.preventDefault();
            if (dirty && name.trim()) save.mutate();
          }}
        >
          <FormRow label="Avatar">
            <div className="flex flex-wrap items-center gap-4">
              <Avatar name={name || "?"} image={image} size="xl" />
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragging(false);
                  void pickFile(e.dataTransfer.files[0]);
                }}
                className={cn(
                  "flex min-w-64 flex-1 cursor-pointer items-center gap-3 rounded-lg border border-dashed px-4 py-3 text-left transition-colors",
                  dragging ? "border-accent bg-accent/[0.06]" : "border-bd-strong hover:border-accent/60 hover:bg-hover/50",
                )}
              >
                <ImagePlus size={18} className="text-muted" />
                <span>
                  <span className="block text-[13px] font-medium">Drop an image or click to upload</span>
                  <span className="block text-xs text-muted">PNG or JPG, resized in your browser to fit 100KB</span>
                </span>
              </button>
              {image && (
                <Button
                  variant="secondary"
                  icon={<Trash2 size={14} />}
                  onClick={() => {
                    setImage(null);
                    setDirty(true);
                  }}
                >
                  Remove
                </Button>
              )}
              <input ref={fileRef} type="file" accept="image/*" hidden onChange={(e) => void pickFile(e.target.files?.[0])} />
            </div>
          </FormRow>
          <FormRow label="Display name">
            <Input
              id="profile-name"
              data-testid="profile-name"
              className="w-full max-w-md"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                setDirty(true);
              }}
            />
          </FormRow>
          {email && (
            <FormRow label="Email" hint="Managed by your sign-in">
              <span className="inline-flex items-center gap-2 text-[13px] text-muted">
                <Lock size={13} /> {email}
              </span>
            </FormRow>
          )}
          <div className="flex items-center gap-3 px-5 py-3.5">
            {error && <p className="text-sm text-deny">{error}</p>}
            <span className="flex-1" />
            {dirty && (
              <Button
                variant="ghost"
                onClick={() => {
                  setDirty(false);
                  setError("");
                }}
              >
                Cancel
              </Button>
            )}
            <Button type="submit" variant="primary" data-testid="profile-save" disabled={!dirty || !name.trim()} loading={save.isPending}>
              Save
            </Button>
          </div>
        </form>
      </SectionCard>
      <Preferences />
    </div>
  );
}

function FormRow({ label, hint, children }: { label: string; hint?: string | undefined; children: React.ReactNode }) {
  return (
    <div className="grid items-center gap-x-6 gap-y-2 px-5 py-4 sm:grid-cols-[160px_1fr]">
      <div>
        <p className="text-[13px] font-medium">{label}</p>
        {hint && <p className="text-xs text-muted">{hint}</p>}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

function Preferences() {
  const [pref, setPref] = useState<ThemePreference>(themePreference);
  useEffect(() => {
    const on = (e: Event) => setPref((e as CustomEvent<ThemePreference>).detail);
    window.addEventListener("varlatch:theme-preference", on);
    return () => window.removeEventListener("varlatch:theme-preference", on);
  }, []);
  return (
    <SectionCard title="Preferences" description="Stored in this browser.">
      <div className="divide-y divide-bd">
        <FormRow label="Theme">
          <Segmented
            value={pref}
            onChange={(p) => chooseThemePreference(p)}
            aria-label="Theme"
            options={[
              { value: "dark", label: "Dark" },
              { value: "light", label: "Light" },
              { value: "system", label: "System" },
            ]}
          />
        </FormRow>
        <FormRow label="Keyboard shortcuts" hint="Press ? anywhere">
          <Button variant="secondary" onClick={() => window.dispatchEvent(new CustomEvent("varlatch:shortcuts"))}>
            View all <Kbd>?</Kbd>
          </Button>
        </FormRow>
      </div>
    </SectionCard>
  );
}
