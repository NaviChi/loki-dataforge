import type { HTMLAttributes, PropsWithChildren } from 'react';
import { cn } from '../../lib/utils';

export function Card({ className, children, ...props }: PropsWithChildren<HTMLAttributes<HTMLDivElement>>) {
  return (
    <div
      className={cn(
        'rounded-2xl border border-border/70 bg-card/90 p-4 shadow-panel backdrop-blur-sm',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}
