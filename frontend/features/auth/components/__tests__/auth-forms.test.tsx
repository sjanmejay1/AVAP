import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/features/auth/api/auth-api", () => ({
  authApi: { login: vi.fn(), register: vi.fn(), logout: vi.fn() },
}));

import { authApi } from "@/features/auth/api/auth-api";
import { LoginForm } from "@/features/auth/components/login-form";
import { RegisterForm } from "@/features/auth/components/register-form";
import { ApiError } from "@/lib/api/errors";
import { renderWithAuth, fakeAuth } from "@/test/render";

const mockedLogin = vi.mocked(authApi.login);
const mockedRegister = vi.mocked(authApi.register);
const tokens = {
  access_token: "t",
  token_type: "bearer",
  expires_in: 900,
  user: { id: "u1", email: "analyst@example.com", created_at: "2026-11-01T00:00:00Z" },
};

async function fillLogin(email: string, password: string) {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Email"), email);
  await user.type(screen.getByLabelText("Password"), password);
  await user.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("LoginForm", () => {
  it("sends the normalized email and starts the session on success", async () => {
    mockedLogin.mockResolvedValue(tokens);
    const auth = fakeAuth({ status: "anonymous", user: null });
    renderWithAuth(<LoginForm />, auth);

    await fillLogin("  Analyst@Example.com ", "correct horse battery");

    await waitFor(() =>
      expect(mockedLogin).toHaveBeenCalledWith({
        email: "analyst@example.com",
        password: "correct horse battery",
      })
    );
    await waitFor(() => expect(auth.startSession).toHaveBeenCalledWith(tokens));
  });

  it("validates before sending anything", async () => {
    renderWithAuth(<LoginForm />, fakeAuth({ status: "anonymous", user: null }));
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("Enter your email address.")).toBeInTheDocument();
    expect(screen.getByText("Enter your password.")).toBeInTheDocument();
    expect(mockedLogin).not.toHaveBeenCalled();
  });

  it.each([
    ["wrong credentials (401)", "UNAUTHORIZED", 401, "Invalid email or password."],
    ["the rate limit (429)", "TOO_MANY_REQUESTS", 429, "Too many attempts. Try again in a minute."],
  ])("shows the backend's message for %s", async (_label, code, status, message) => {
    mockedLogin.mockRejectedValue(new ApiError({ code, message, status }));
    renderWithAuth(<LoginForm />, fakeAuth({ status: "anonymous", user: null }));

    await fillLogin("analyst@example.com", "whatever");

    expect(await screen.findByRole("alert")).toHaveTextContent(message);
  });

  it("shows a notice passed by the page, such as an expired session", () => {
    renderWithAuth(
      <LoginForm notice="Your session ended. Sign in again to continue." />,
      fakeAuth({ status: "anonymous", user: null })
    );
    expect(screen.getByRole("status")).toHaveTextContent("Your session ended.");
  });
});

describe("RegisterForm", () => {
  async function fillRegister(password: string, confirm: string) {
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Email"), "new@example.com");
    await user.type(screen.getByLabelText("Password"), password);
    await user.type(screen.getByLabelText("Confirm password"), confirm);
    await user.click(screen.getByRole("button", { name: "Create account" }));
  }

  it("requires at least 12 characters and matching passwords", async () => {
    renderWithAuth(<RegisterForm />, fakeAuth({ status: "anonymous", user: null }));

    await fillRegister("short", "different");

    expect(await screen.findByText("Use at least 12 characters.")).toBeInTheDocument();
    expect(screen.getByText("The passwords don't match.")).toBeInTheDocument();
    expect(mockedRegister).not.toHaveBeenCalled();
  });

  it("registers without sending the confirmation field, then starts the session", async () => {
    mockedRegister.mockResolvedValue(tokens);
    const auth = fakeAuth({ status: "anonymous", user: null });
    renderWithAuth(<RegisterForm />, auth);

    await fillRegister("a long enough passphrase", "a long enough passphrase");

    await waitFor(() =>
      expect(mockedRegister).toHaveBeenCalledWith({
        email: "new@example.com",
        password: "a long enough passphrase",
      })
    );
    await waitFor(() => expect(auth.startSession).toHaveBeenCalledWith(tokens));
  });

  it("maps a backend 422 onto the field it names", async () => {
    mockedRegister.mockRejectedValue(
      new ApiError({
        code: "VALIDATION_ERROR",
        message: "Request validation failed",
        status: 422,
        details: { errors: [{ loc: ["body", "password"], msg: "Value error, Password must not be your email address." }] },
      })
    );
    renderWithAuth(<RegisterForm />, fakeAuth({ status: "anonymous", user: null }));

    await fillRegister("a long enough passphrase", "a long enough passphrase");

    expect(await screen.findByText("Password must not be your email address.")).toBeInTheDocument();
  });
});
