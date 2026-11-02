export interface PublicSite {
  site_name: string;
  subtitle: string;
}

const EMPTY: PublicSite = { site_name: '', subtitle: '' };

export function invalidateSite() {}

export function useSite(): PublicSite {
  return EMPTY;
}
