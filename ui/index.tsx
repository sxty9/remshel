import { TerminalIcon, type HolisticUser, type ServicePlugin } from '@holistic/ui';
import { Console } from './Console';

// Visible only to users who actually have shell access. remshel's right is the user's Linux
// login shell — a shell-type right with NO backing group — surfaced on the user as
// `shellEnabled`, so the default hp_<id>_* sidebar gate can't apply here. Admins always see it.
function canSeeRemshel(user: HolisticUser): boolean {
  return user.isAdmin || user.shellEnabled === true;
}

// remshel's dashboard plugin. Linked into holistic/frontend/external/remshel at install
// time and discovered by the host SPA's build-time registry. `id` MUST equal the link dir
// name and the permissions manifest's "service" field.
const plugin: ServicePlugin = {
  id: 'remshel',
  displayName: 'Remote Shell',
  icon: TerminalIcon,
  order: 30,
  visible: canSeeRemshel,
  Component: Console,
};

export default plugin;
