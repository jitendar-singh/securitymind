// Inline SVG for CrowdStrike (no brand mark exists in react-icons/si or
// FontAwesome). Stylized falcon silhouette — recognizable but not pixel-
// identical to the official mark. Inherits color from currentColor and accepts
// `size` (number or string) like react-icons.
export default function CrowdStrikeIcon({ size = 16, strokeWidth: _sw, ...rest }) {
  const dim = typeof size === "number" ? `${size}px` : size;
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width={dim}
      height={dim}
      fill="currentColor"
      aria-hidden="true"
      {...rest}
    >
      {/* Diving falcon — sharp head + swept-back wings + tail */}
      <path d="M21.6 4.6c-1.7 1.4-3.6 2.6-5.6 3.4-.7.3-1.5.5-2.2.7l-1.3-2 .8-.8a.6.6 0 0 0-.4-1l-1.6.1.6-1.4a.5.5 0 0 0-.7-.7l-1.4 1c-.4.3-.6.7-.6 1.1l.1 1.4-2.8 1.5c-.5.3-.7.9-.4 1.4l1 1.7L4 11.7l-1.3.5a.5.5 0 0 0 0 .9l1.7.7-.7 1.7c-.2.5.3.9.8.7l1.7-.7.7 1.7c.2.5.9.5 1 0l.5-1.3 1.7-3.1 1.7 1c.5.3 1.1.1 1.4-.4l1.5-2.8 1.4.1c.4 0 .8-.2 1-.5l1.1-1.5a.5.5 0 0 0-.7-.7l-1.4.6.1-1.6a.6.6 0 0 0-1-.4l-.8.8-2-1.3c.2-.7.4-1.5.7-2.2.8-2 2-3.9 3.4-5.6Z" />
    </svg>
  );
}
