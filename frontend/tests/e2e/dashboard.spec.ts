import { expect, test } from "@playwright/test";

test("opens dashboard and selects a device through quick selector", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "IoT Signal Watch" })).toBeVisible();
  await page.getByRole("button", { name: /garage cam/i }).click();

  await expect(page.getByText(/Garage Cam/i)).toBeVisible();
  await expect(page.getByText(/Outage \+ Security Agent/i)).toBeVisible();
});
