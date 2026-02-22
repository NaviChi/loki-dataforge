import type { ButtonHTMLAttributes, PropsWithChildren } from 'react';
import { cn } from '../../lib/utils';

type Variant = 'default' | 'secondary' | 'ghost' | 'danger';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
}

const variantClass: Record<Variant, string> = {
  default: 'bg-accent text-white hover:brightness-110',
  secondary: 'bg-white/10 text-foreground hover:bg-white/20 border border-border',
  ghost: 'bg-transparent text-foreground hover:bg-white/10',
  danger: 'bg-rose-600 text-white hover:bg-rose-500',
};

export function Button({
  children,
  className,
  variant = 'default',
  ...props
}: PropsWithChildren<ButtonProps>) {
  return (
    <button
      className={cn(
        'inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        variantClass[variant],
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}
