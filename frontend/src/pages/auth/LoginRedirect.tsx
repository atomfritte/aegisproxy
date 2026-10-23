import React from 'react';
import { Redirect } from '../../lib/router';

/** /login while signed in (e.g. after a password sign-in on /login?sso_error=…): go to the overview. */
export const LoginRedirect: React.FC = () => <Redirect to="/" />;
