import { render, screen } from "@testing-library/react";

import Home from "../app/page";

describe("Home Page", () => {
  it("renders the main heading", () => {
    render(<Home />);

    const heading = screen.getByRole("heading", {
      name: /ai dev platform/i,
    });

    expect(heading).toBeInTheDocument();
  });

  it("renders the description", () => {
    render(<Home />);

    const description = screen.getByText(
      /a secure, ai-powered development platform/i,
    );

    expect(description).toBeInTheDocument();
  });

  it("renders navigation links", () => {
    render(<Home />);

    const getStartedLink = screen.getByRole("link", {
      name: /get started/i,
    });
    const learnMoreLink = screen.getByRole("link", {
      name: /learn more/i,
    });

    expect(getStartedLink).toBeInTheDocument();
    expect(learnMoreLink).toBeInTheDocument();
  });

  it("renders feature cards", () => {
    render(<Home />);

    expect(screen.getByText("Security First")).toBeInTheDocument();
    expect(screen.getByText("AI-Powered")).toBeInTheDocument();
    expect(screen.getByText("Modern Stack")).toBeInTheDocument();
  });
});
