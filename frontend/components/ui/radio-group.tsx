"use client"

import * as React from "react"
import { RadioGroup as RadioGroupPrimitive } from "radix-ui"

import { cn } from "@/lib/utils"

function RadioGroup({
  className,
  ...props
}: React.ComponentProps<typeof RadioGroupPrimitive.Root>) {
  return (
    <RadioGroupPrimitive.Root
      data-slot="radio-group"
      className={cn("grid gap-3", className)}
      {...props}
    />
  )
}

/**
 * A full-width selectable option: the whole bordered block is the radio, so
 * the hit area is large and the label and description are read with it.
 */
function RadioGroupCard({
  className,
  children,
  ...props
}: React.ComponentProps<typeof RadioGroupPrimitive.Item>) {
  return (
    <RadioGroupPrimitive.Item
      data-slot="radio-group-card"
      className={cn(
        "group flex w-full cursor-pointer items-start gap-3 rounded-lg border border-border p-4 text-left transition-colors outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:border-foreground",
        className
      )}
      {...props}
    >
      <span
        aria-hidden="true"
        className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border border-input group-data-[state=checked]:border-foreground"
      >
        <RadioGroupPrimitive.Indicator className="size-2 rounded-full bg-foreground" />
      </span>
      <span className="flex min-w-0 flex-col gap-1">{children}</span>
    </RadioGroupPrimitive.Item>
  )
}

export { RadioGroup, RadioGroupCard }
