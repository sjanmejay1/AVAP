import type { Metadata } from "next";

import { RegisterForm } from "@/features/auth/components/register-form";

export const metadata: Metadata = { title: "Create an account" };

export default function RegisterPage() {
  return (
    <section className="flex flex-col gap-6" aria-labelledby="register-heading">
      <h1 id="register-heading" className="text-h2">
        Create an account
      </h1>
      <RegisterForm />
    </section>
  );
}
