// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from "react";
import { KeyRound, QrCode } from "lucide-react";
import { Dialog } from "../../components/Dialog";
import { Button, Field, Input } from "../../components/ui";
import { errorMessage } from "../../shell/Shell";
import { ITEM_NAME_PATTERN, seedProblem } from "./model";
import { qrReader } from "./qr";

/**
 * Store the seed of one-time codes (ADR-0061): an otpauth:// URI, pasted, or
 * read from a QR image in this browser where the browser itself can (the
 * image never leaves it). Saved on its own, never as a draft: nothing on the
 * page keeps it, and it is gone from this dialog when it closes.
 */
export function SeedDialog({
  open,
  item,
  project,
  env,
  exists,
  onClose,
  onSave,
}: {
  open: boolean;
  /** The item whose seed is replaced; absent to add one. */
  item?: string | undefined;
  project: string;
  env: string;
  exists: (name: string) => boolean;
  onClose: () => void;
  /** Throws to keep the dialog open with the error shown. */
  onSave: (name: string, otpauth: string) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [uri, setUri] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const file = useRef<HTMLInputElement>(null);
  const readQr = qrReader();

  useEffect(() => {
    setName("");
    setUri("");
    setError("");
  }, [open, item]);

  const target = item ?? name;
  const taken = item === undefined && name !== "" && exists(name);
  const problem = uri === "" ? null : seedProblem(uri);
  const ready = ITEM_NAME_PATTERN.test(target) && !taken && uri !== "" && !problem && !busy;

  const submit = async () => {
    if (!ready) return;
    setBusy(true);
    setError("");
    try {
      await onSave(target, uri.trim());
      setUri("");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const fromImage = async (image: Blob | undefined) => {
    if (!image || !readQr) return;
    setError("");
    try {
      const text = await readQr(image);
      if (text === null) setError("No QR code was found in that image.");
      else if (seedProblem(text)) setError("That QR code holds no otpauth:// URI.");
      else setUri(text);
    } catch {
      setError("That image could not be read.");
    }
  };

  return (
    <Dialog
      open={open}
      onClose={() => !busy && onClose()}
      size="md"
      data-testid="seed-dialog"
      icon={
        <span className="flex size-9 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
          <KeyRound size={16} />
        </span>
      }
      title={
        item ? (
          <>
            Replace the seed of <span className="font-mono">{item}</span>
          </>
        ) : (
          "Add a one-time code"
        )
      }
      description={
        <span className="font-mono text-[12.5px]">
          {project} / {env}
        </span>
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="confirm-seed" disabled={!ready} loading={busy} onClick={() => void submit()}>
            {item ? "Replace" : "Add"}
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <p className="text-[13px] text-muted">
          What an authenticator app scans when two-factor sign-in is set up. Varlatch makes the codes: a Broker gets the code of the moment, and
          no retrieval, sync or export delivers the seed. The issuer and the account in it can be read by whoever may see that the item exists.
        </p>
        {item === undefined && (
          <Field label="Item" htmlFor="seed-name">
            <Input
              id="seed-name"
              data-testid="seed-name"
              data-autofocus
              mono
              placeholder="PORTAL_OTP"
              value={name}
              invalid={taken || (name !== "" && !ITEM_NAME_PATTERN.test(name))}
              title={taken ? `${name} already has a value in ${env}` : undefined}
              onChange={(e) => setName(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_"))}
            />
          </Field>
        )}
        <Field
          label="otpauth:// URI"
          htmlFor="seed-uri"
          hint="When only a key is shown: otpauth://totp/Name?secret= followed by the key."
        >
          <div className="flex gap-2">
            <Input
              id="seed-uri"
              data-testid="seed-uri"
              mono
              type="password"
              autoComplete="off"
              spellCheck={false}
              className="min-w-0 flex-1"
              placeholder="otpauth://totp/…"
              value={uri}
              invalid={problem !== null}
              onChange={(e) => setUri(e.target.value)}
            />
            {readQr && (
              <>
                <input
                  ref={file}
                  type="file"
                  accept="image/*"
                  hidden
                  data-testid="seed-qr"
                  onChange={(e) => {
                    const image = e.target.files?.[0];
                    e.target.value = "";
                    void fromImage(image);
                  }}
                />
                <Button icon={<QrCode size={14} />} onClick={() => file.current?.click()} title="Read in this browser; the image is not sent anywhere">
                  QR image
                </Button>
              </>
            )}
          </div>
        </Field>
        {(problem || error) && (
          <p className="text-[13px] text-deny" data-testid="seed-error">
            {error || problem}
          </p>
        )}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
