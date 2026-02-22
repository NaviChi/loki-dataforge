import { cn } from '../../lib/utils';

interface TabsProps {
  value: string;
  onChange: (next: string) => void;
  options: Array<{ id: string; label: string }>;
}

export function Tabs({ value, onChange, options }: TabsProps) {
  return (
    <div className="inline-flex rounded-xl border border-border bg-black/20 p-1">
      {options.map((option) => (
        <button
          key={option.id}
          onClick={() => onChange(option.id)}
          className={cn(
            'rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors',
            option.id === value
              ? 'bg-accent text-white'
              : 'text-foreground/70 hover:text-foreground',
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
