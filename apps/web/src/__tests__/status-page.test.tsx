import { render, screen } from "@testing-library/react";

import { fetchSystemStatus } from "../lib/system-status";

jest.mock("@/lib/system-status", () => ({
  fetchSystemStatus: jest.fn(),
}));

const mockedFetchSystemStatus = jest.mocked(fetchSystemStatus);

describe("StatusPage", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("renders system status information when the API responds", async () => {
    mockedFetchSystemStatus.mockResolvedValue({
      status: "Operational",
      services: ["Frontend", "API Gateway", "Database (Mock)"],
      timestamp: "2024-01-01T00:00:00.000Z",
    });

    const Page = (await import("../app/status/page")).default;
    render(await Page());

    expect(screen.getByText("Platform Status")).toBeInTheDocument();
    expect(screen.getByText("Operational")).toBeInTheDocument();
    expect(screen.getByText("Frontend")).toBeInTheDocument();
    expect(screen.getByText("Database (Mock)")).toBeInTheDocument();
    expect(screen.getByText("2024-01-01T00:00:00.000Z")).toBeInTheDocument();
  });

  it("renders an error message when the API request fails", async () => {
    mockedFetchSystemStatus.mockRejectedValue(new Error("Network error"));

    const Page = (await import("../app/status/page")).default;
    render(await Page());

    expect(
      screen.getByText(/Unable to load system status/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Network error/i)).toBeInTheDocument();
  });
});
