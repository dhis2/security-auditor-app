import { CustomDataProvider } from '@dhis2/app-runtime'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'

// Opt in to React's act() environment so state updates are flushed
// deterministically instead of leaking across tests.
global.IS_REACT_ACT_ENVIRONMENT = true

// `act` is imported from 'react' rather than 'react-dom/test-utils': the
// latter warns on React 18.3 and was removed in React 19.
const tick = async () => {
    await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 0))
    })
}

/**
 * Mount App against a mock data layer.
 *
 * `settle: false` leaves the component in its first render pass, which is the
 * only way to observe the loading state -- useDataQuery resolves on a later
 * tick, so anything that flushes will already be past it.
 */
const mount = async (data, { settle = true } = {}) => {
    const container = document.createElement('div')
    document.body.appendChild(container)
    const root = createRoot(container)

    await act(async () => {
        root.render(
            <CustomDataProvider data={data}>
                <App />
            </CustomDataProvider>
        )
    })

    if (settle) {
        // A few ticks: the query resolves, then the resulting state update
        // renders. One tick is not always enough.
        for (let i = 0; i < 5; i++) {
            await tick()
        }
    }

    return {
        container,
        find: (selector) => container.querySelector(selector),
        text: () => container.textContent,
        unmount: async () => {
            await act(async () => root.unmount())
            container.remove()
        },
    }
}

// Once the user is authorised, App mounts the providers, which fetch system
// info and the saved config. Both must be mocked or the data layer logs an
// error for the unmatched resource.
const authorisedData = (authorities) => ({
    me: { authorities },
    'system/info': {
        version: '2.42.0',
        revision: 'abc1234',
        serverDate: '2026-01-01T00:00:00.000',
    },
    'dataStore/security-auditor-app/config': {},
})

const LOADER = '[data-test="dhis2-uicore-circularloader"]'
const NOTICE = '[data-test="dhis2-uicore-noticebox"]'
const NOTICE_TITLE = '[data-test="dhis2-uicore-noticebox-content-title"]'
const NOTICE_MESSAGE = '[data-test="dhis2-uicore-noticebox-content-message"]'

describe('App', () => {
    let consoleErrors

    beforeEach(() => {
        consoleErrors = []
        jest.spyOn(console, 'error').mockImplementation((...args) => {
            consoleErrors.push(args.join(' '))
        })
    })

    afterEach(() => {
        console.error.mockRestore()
    })

    it('shows a loading indicator while the current user is being fetched', async () => {
        const view = await mount(authorisedData(['ALL']), { settle: false })

        expect(view.find(LOADER)).not.toBeNull()

        await view.unmount()
    })

    it('renders an error notice when the current user cannot be loaded', async () => {
        const view = await mount({
            me: () => Promise.reject(new Error('network down')),
        })

        const notice = view.find(NOTICE)
        expect(notice).not.toBeNull()
        expect(notice.className).toContain('error')
        expect(view.find(NOTICE_MESSAGE).textContent).toBe(
            'Failed to load user information'
        )

        await view.unmount()
    })

    it('denies access to a user without the required authority', async () => {
        const view = await mount({ me: { authorities: ['F_METADATA_IMPORT'] } })

        const notice = view.find(NOTICE)
        expect(notice).not.toBeNull()
        expect(notice.className).toContain('warning')
        expect(view.find(NOTICE_TITLE).textContent).toBe(
            'Administrator Access Required'
        )
        // The message interpolates both authority names via i18n.
        expect(view.find(NOTICE_MESSAGE).textContent).toContain('F_SYSTEM_SETTING')

        await view.unmount()
    })

    it.each([['ALL'], ['F_SYSTEM_SETTING']])(
        'renders the auditor for a user with the %s authority',
        async (authority) => {
            const view = await mount(authorisedData([authority]))

            expect(view.find(LOADER)).toBeNull()
            expect(view.text()).toContain('Security Auditor')
            expect(view.text()).not.toContain('Administrator Access Required')
            // The auditor panel itself, not just the app shell heading.
            expect(view.text()).toContain(
                'Run the security audit against this DHIS2 instance'
            )

            await view.unmount()
        }
    )

    it('renders without React warnings or errors', async () => {
        const view = await mount(authorisedData(['ALL']))
        await view.unmount()

        expect(consoleErrors).toEqual([])
    })
})
