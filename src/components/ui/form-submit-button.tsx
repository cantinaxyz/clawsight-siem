/**
 * @fileoverview ClawSight SIEM module: platform/src/components/ui/form-submit-button.tsx.
 */
"use client";

import * as React from "react";
import { useFormStatus } from "react-dom";
import { Button } from "@/components/ui/button";

type FormSubmitButtonProps = React.ComponentProps<typeof Button> & {
  pendingText?: string;
};

export default function FormSubmitButton({
  children,
  disabled,
  pendingText = "Saving...",
  ...props
}: FormSubmitButtonProps) {
  const { pending } = useFormStatus();

  return (
    <Button {...props} disabled={pending || disabled} aria-busy={pending}>
      {pending ? pendingText : children}
    </Button>
  );
}
