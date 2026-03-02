const ICONS = {
  SAFE:       '🟢',
  SUSPICIOUS: '🟡',
  INJECTION:  '🟠',
  JAILBREAK:  '🔴',
};

export default function SeverityBadge({ classification, size = 'md' }) {
  if (!classification) return null;
  return (
    <span className={`severity-badge ${classification}`}
          style={size === 'lg' ? { fontSize: '14px', padding: '7px 18px' } : {}}>
      {ICONS[classification] || '⚪'} {classification}
    </span>
  );
}
