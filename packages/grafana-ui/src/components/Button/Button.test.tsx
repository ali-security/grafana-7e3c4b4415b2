import { render, screen } from '@testing-library/react';

import { LinkButton } from './Button';

describe('LinkButton', () => {
  it('sanitizes javascript: URLs in href', () => {
    render(<LinkButton href="javascript:alert(1)">Click me</LinkButton>);
    expect(screen.getByRole('link')).toHaveAttribute('href', 'about:blank');
  });

  it('preserves safe URLs in href', () => {
    render(<LinkButton href="https://grafana.com/docs">Click me</LinkButton>);
    expect(screen.getByRole('link')).toHaveAttribute('href', 'https://grafana.com/docs');
  });

  it('preserves relative URLs in href', () => {
    render(<LinkButton href="/dashboards">Click me</LinkButton>);
    expect(screen.getByRole('link')).toHaveAttribute('href', '/dashboards');
  });

  it('omits href attribute when not provided', () => {
    render(<LinkButton>No link</LinkButton>);
    expect(screen.getByText('No link').closest('a')).not.toHaveAttribute('href');
  });

  it('passes through empty string href unchanged', () => {
    render(<LinkButton href="">Current page</LinkButton>);
    expect(screen.getByText('Current page').closest('a')).toHaveAttribute('href', '');
  });
});
