import { apiGetWidgetsByType, apiGetWidgetsAdmin } from '../util/api'
import React, { useState, useRef, useEffect } from 'react'
import { useQuery } from 'react-query'

import Header from './header'
import WidgetInstall from './widget-install'
import WidgetList from './widget-list'

const WidgetAdminPage = () => {
	const [widgets, setWidgets] = useState([])
	
	const { data, isLoading} = useQuery({
		queryKey: 'admin-widgets',
		queryFn: apiGetWidgetsAdmin,
		staleTime: Infinity,
		onSuccess: (widgets) => {
			widgets.forEach((w) => {
				w.icon = Materia.Image.iconUrl(w.dir, 60)
				// Convert "0" and "1" to false and true
				w.in_catalog = !!+w.in_catalog
				w.is_editable = !!+w.is_editable
				w.restrict_publish = !!+w.restrict_publish
				w.is_scorable = !!+w.is_scorable
				w.is_playable = !!+w.is_playable
				w.is_answer_encrypted = !!+w.is_answer_encrypted
				w.is_qset_encrypted = !!+w.is_qset_encrypted
				w.is_storage_enabled = !!+w.is_storage_enabled
				w.is_scalable = !!+w.is_scalable
			})
			setWidgets(widgets)
		}
	})

	let pageRenderContent = (
        <>
            <WidgetInstall/>
            <WidgetList widgets={widgets} isLoading={isLoading}/>
        </>
    )

	return (
		<>
			<Header />
			<div className="widget-admin-page">
				<div>
					{ pageRenderContent }
				</div>
			</div>
		</>
	)
}

export default WidgetAdminPage
