import { beforeEach, describe, expect, it, vi } from "vitest";

const { headersMock, notFoundMock, authorizeAdminRequestMock } = vi.hoisted(() => ({
  headersMock: vi.fn(),
  notFoundMock: vi.fn(),
  authorizeAdminRequestMock: vi.fn(),
}));

vi.mock("next/headers", () => ({
  headers: headersMock,
}));

vi.mock("next/navigation", () => ({
  notFound: notFoundMock,
}));

vi.mock("@/lib/auth", () => ({
  authorizeAdminRequest: authorizeAdminRequestMock,
}));

import { requireAdminPageAuth, requireAdminServerActionAuth } from "@/lib/server-action-auth";

describe("server action/page auth enforcement", () => {
  beforeEach(() => {
    headersMock.mockReset();
    notFoundMock.mockReset();
    authorizeAdminRequestMock.mockReset();
    headersMock.mockResolvedValue(new Headers());
    authorizeAdminRequestMock.mockReturnValue(null);
  });

  it("rejects unauthorized page rendering", async () => {
    authorizeAdminRequestMock.mockReturnValue(
      Response.json({ error: "Unauthorized" }, { status: 401 }),
    );
    notFoundMock.mockImplementation(() => {
      throw new Error("not-found");
    });

    await expect(requireAdminPageAuth()).rejects.toThrow("not-found");

    expect(notFoundMock).toHaveBeenCalledTimes(1);
    expect(authorizeAdminRequestMock).toHaveBeenCalledTimes(1);
  });

  it("allows authorized page rendering", async () => {
    headersMock.mockResolvedValue(new Headers({ authorization: "Bearer admin-token" }));

    await expect(requireAdminPageAuth()).resolves.toBeUndefined();

    expect(notFoundMock).not.toHaveBeenCalled();
    expect(authorizeAdminRequestMock).toHaveBeenCalledTimes(1);
    const req = authorizeAdminRequestMock.mock.calls[0]?.[0] as Request;
    expect(req.headers.get("authorization")).toBe("Bearer admin-token");
  });

  it("throws in server actions when unauthorized", async () => {
    authorizeAdminRequestMock.mockReturnValue(
      Response.json({ error: "Unauthorized" }, { status: 401 }),
    );

    await expect(requireAdminServerActionAuth()).rejects.toThrow("Unauthorized");
    expect(authorizeAdminRequestMock).toHaveBeenCalledTimes(1);
  });
});
