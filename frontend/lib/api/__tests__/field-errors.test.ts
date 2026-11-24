import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api/errors";
import { fieldErrorsFrom } from "@/lib/api/field-errors";

function validationError(errors: unknown) {
  return new ApiError({
    code: "VALIDATION_ERROR",
    message: "Request validation failed",
    status: 422,
    details: { errors },
  });
}

describe("fieldErrorsFrom", () => {
  it("maps Pydantic body errors to field messages, dropping the 'Value error, ' prefix", () => {
    const error = validationError([
      { loc: ["body", "email"], msg: "Value error, Enter a valid email address.", type: "value_error" },
      { loc: ["body", "password"], msg: "String should have at least 12 characters", type: "string_too_short" },
    ]);

    expect(fieldErrorsFrom(error)).toEqual({
      email: "Enter a valid email address.",
      password: "String should have at least 12 characters",
    });
  });

  it("keeps the first message per field and ignores non-body locations", () => {
    const error = validationError([
      { loc: ["body", "email"], msg: "first" },
      { loc: ["body", "email"], msg: "second" },
      { loc: ["query", "limit"], msg: "too big" },
    ]);

    expect(fieldErrorsFrom(error)).toEqual({ email: "first" });
  });

  it("returns nothing for non-validation errors or missing details", () => {
    expect(
      fieldErrorsFrom(new ApiError({ code: "UNAUTHORIZED", message: "No", status: 401 }))
    ).toEqual({});
    expect(
      fieldErrorsFrom(new ApiError({ code: "VALIDATION_ERROR", message: "No", status: 422 }))
    ).toEqual({});
  });
});
