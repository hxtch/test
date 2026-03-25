import UIAbility from '@ohos.app.ability.UIAbility';
import window from '@ohos.window';
import hilog from '@ohos.hilog';
import Want from '@ohos.app.ability.Want';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import router from '@ohos.router';

const TAG = 'InternalPayAbility';
const DOMAIN = 0x0000;

const ORDER_ID_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

const ALLOWED_CALLBACK_PREFIXES: string[] = [
  'mallapp://',
  'proapp://',
  'https://pay.mycompany.com'
];

function isCallbackAllowed(callbackUrl: string): boolean {
  return ALLOWED_CALLBACK_PREFIXES.some(prefix => callbackUrl.startsWith(prefix));
}

export default class InternalPayAbility extends UIAbility {
  private orderId: string = '';
  private callbackUrl: string = '';

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, TAG, 'onCreate called');
    this.parseWantParams(want);
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, TAG, 'onNewWant called');
    this.parseWantParams(want);
  }

  private parseWantParams(want: Want): void {
    let orderId = '';
    let callbackUrl = '';

    // Try parsing from URI first (deep link invocation)
    if (want.uri) {
      try {
        const url = new URL(want.uri);
        orderId = url.searchParams.get('orderId') ?? '';
        callbackUrl = url.searchParams.get('callbackUrl') ?? '';
      } catch (e) {
        hilog.error(DOMAIN, TAG, 'Failed to parse want.uri: %{public}s', String(e));
      }
    }

    // Fallback: read from want.parameters (explicit Want calls)
    if (!orderId && want.parameters) {
      orderId = (want.parameters['orderId'] as string) ?? '';
      callbackUrl = (want.parameters['callbackUrl'] as string) ?? '';
    }

    // Validate orderId
    if (!ORDER_ID_PATTERN.test(orderId)) {
      hilog.error(DOMAIN, TAG, 'Invalid orderId: %{public}s', orderId);
      this.context.terminateSelf();
      return;
    }

    // Validate callbackUrl
    if (callbackUrl && !isCallbackAllowed(callbackUrl)) {
      hilog.error(DOMAIN, TAG, 'Rejected callbackUrl: %{public}s', callbackUrl);
      this.context.terminateSelf();
      return;
    }

    this.orderId = orderId;
    this.callbackUrl = callbackUrl;
    hilog.info(DOMAIN, TAG, 'Params parsed — orderId: %{public}s', this.orderId);
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    hilog.info(DOMAIN, TAG, 'onWindowStageCreate');

    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, 'Failed to load content: %{public}s', JSON.stringify(err));
        return;
      }

      // Navigate to PayConfirmPage after shell page loads
      router.pushUrl({
        url: 'pages/PayConfirmPage',
        params: {
          orderId: this.orderId,
          callbackUrl: this.callbackUrl
        }
      }).catch((e: Error) => {
        hilog.error(DOMAIN, TAG, 'Router push failed: %{public}s', String(e));
      });
    });
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'onDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, TAG, 'onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, TAG, 'onBackground');
  }
}
