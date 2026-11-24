import { redirect } from "next/navigation";

/** The targets list is the home page. */
export default function HomePage() {
  redirect("/targets");
}
