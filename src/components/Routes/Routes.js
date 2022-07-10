import React from 'react'
import { Switch, Route, Redirect } from 'react-router-dom'
import Home from '../../pages/home/Home.js'
import { sections } from '../../pages/sections.conf.js'

const MyRoutes = () => (
    <Switch>
        <Route exact path="/" component={Home} />
        {sections.map((section) => (
            <Route
                key={section.key}
                exact
                path={section.path}
                component={(props) => (
                    <section.component sectionKey={section.key} {...props} />
                )}
            />
        ))}
        <Redirect from="*" to="/" />
    </Switch>
)

export default MyRoutes
