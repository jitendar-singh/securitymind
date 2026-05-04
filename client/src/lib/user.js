// Initials from a user's name or email — used as the avatar glyph when we
// don't have an image URL.
export function userInitials(user) {
  if (!user) return "?";
  const source = (user.name || user.email || "").trim();
  if (!source) return "?";
  const parts = source.split(/[\s@._-]+/).filter(Boolean);
  if (parts.length === 0) return source[0].toUpperCase();
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}
