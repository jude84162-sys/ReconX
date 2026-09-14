"use client";

import { UserButton } from "@clerk/nextjs";

export function AccountButton() {
  if (!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY ||
      process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY.includes("replace_me")) return null;
  return <UserButton afterSignOutUrl="/" />;
}
