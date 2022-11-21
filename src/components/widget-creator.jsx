import React, { useState, useEffect, useRef } from 'react';
import { useQuery } from 'react-query'
import LoadingIcon from './loading-icon';
import { apiGetWidgetInstance, apiGetQuestionSet, apiCanBePublishedByCurrentUser, apiSaveWidget, apiGetWidgetLock, apiGetWidget, apiAuthorVerify} from '../util/api'
import NoPermission from './no-permission'
import Alert from './alert'

const WidgetCreator = ({instId, setInstanceId, widgetId, minHeight='', minWidth='', creatorGuideUrl}) => {
	const [alertDialog, setAlertDialog] = useState({
		enabled: false,
		msg: '',
		title: '',
		fatal: false,
		enableLoginButton: false
	});
	const [widgetData, setWidgetData] = useState({
		loading: true,
		htmlPath: null,
		hasCreatorGuide: false,
		creatorGuideUrl: creatorGuideUrl
	});
	
	// qset storage for previous save feature
	// current working qset, temporarily cached to await confirm/cancel
	const [qsetToBeCached, setQsetToBeCached] = useState({});
	// qset selected to be loaded after requested reload
	const [qsetToReload, setQsetToReload] = useState({});
	const [keepQSet, setKeepQSet] = useState({});
	const [keepQSetIsLoading, setKeepQSetIsLoading] = useState(true);
	const [invalid, setInvalid] = useState(null);
	
	const [creatorReady, setCreatorReady] = useState(false);
	const [embedDialogType, setEmbedDialogType] = useState('embed_dialog');
	const [modal, setModal] = useState(false);
	const [iframeUrl, setIframeUrl] = useState(null);
	const [showActionBar, setShowActionBar] = useState(true);
	const [showRollbackConfirmBar, setShowRollbackConfirmBar] = useState(null)
	const [showQsetHistoryDialog, setShowQsetHistoryDialog] = useState(false);
	const [height, setHeight] = useState(null);
	const [heartbeatEnabled, toggleHeartbeat] = useState(true)
	const [startTime, setStartTime] = useState(0);
	const frameRef = useRef(null);
	const [updateMode, setUpdateMode] = useState(null);
	// How far from the top of the window that the creator frame starts
	const [bottomOffset, setBottomOffset] = useState(145);
	const [mediaFile, setMediaFile] = useState(null);
	const saveModeRef = useRef(null);
	const [popup, setPopup] = useState('')
	const [saveStatus, setSaveStatus] = useState('idle');
	const [previewText, setPreviewText] = useState('Preview');
	const [saveText, setSaveText] = useState('Save Draft');
	const [publishText, setPublishText] = useState('Publish...')
	const [previewUrl, setPreviewUrl] = useState(null);
	const [returnUrl, setReturnUrl] = useState(null);
	const [returnPlace, setReturnPlace] = useState(null);

	const [nonEditable, setNonEditable] = useState(null);

	// Gets widget instance
	const { isLoading: instanceIsLoading, data: widgetInstance } = useQuery({
		queryKey: ['widget-inst', instId],
		queryFn: () => apiGetWidgetInstance(instId),
		// Uncomment to test network delay
		// () => new Promise(resolve => setTimeout(() => resolve(apiGetWidgetInstance(instId)), 5000)),
		enabled: !!instId,
		staleTime: Infinity,
		onSuccess: (data => {
			if (!data || Object.keys(data).length == 0) {
				_alert(`Instance not found`)
				// Clear instance id
				setInstanceId('')
			}
		})
	})

	// Gets widget info
	const { isLoading: widgetInfoIsLoading, data: widgetInfo } = useQuery({
		queryKey: ['widget-inst', widgetId],
		queryFn: () => apiGetWidget(widgetId),
		enabled: !!widgetId,
		staleTime: Infinity
	})

	// Gets qset if instId is not null
	const { isLoading: qSetIsLoading, data: qset } = useQuery({
		queryKey: ['qset', widgetInstance],
		queryFn: () => apiGetQuestionSet(instId),
			// Uncomment to test network delay
			// () => new Promise(resolve => setTimeout(() => resolve(apiGetQuestionSet(instId)), 2000)),
		staleTime: Infinity,
		placeholderData: null,
		enabled: !!widgetInstance && !!instId,
		onSettled: data => {
			if ( (data ? data.title : undefined) === 'Permission Denied' || (data ? data.title : undefined) === 'error') {
				setInvalid(true);
				onInitFail('Permission Denied')
				setKeepQSet(null)
			} else if (!data) {
				onInitFail('Unable to load widget data.')
				setKeepQSet(null)
			} else {
				setInvalid(false);
				setKeepQSet(data);
			}
		}
	})

	// if this is an existing instance, check lock status
	const { data: isLocked } = useQuery({
		queryKey: ['widget-lock', instId],
		queryFn: () => apiGetWidgetLock(instId),
		enabled: !!instId,
		onSettled: (success) => {
			if (!success) {
				onInitFail('Someone else is editing this widget, you will be able to edit after they finish.')
			}
		}
	})

	// Checks whether the flag 'restrict_publish' is set to true on the widget
	const { data: canPublish } = useQuery({
		queryKey: ['can-publish', widgetId],
		queryFn: () => apiCanBePublishedByCurrentUser(widgetId || (widgetInstance ? widgetInstance.widget.id : (widgetInfo ? widgetInfo.id : ''))),
		staleTime: Infinity
	})

	useEffect(() => {
		if (widgetInstance && canPublish === false && !widgetInstance.is_draft) {
			onInitFail('Widget type can not be edited by students after publishing.')
		}
	}, [canPublish, widgetInstance])

	useQuery({
		queryKey: 'heartbeat',
		queryFn: () => apiAuthorVerify(),
		staleTime: 30000,
		refetchInterval: 30000,
		enabled: heartbeatEnabled,
		onSettled: (valid) => {
			if (!valid) {
				toggleHeartbeat(false)
				_alert('You have been logged out due to inactivity', 'Invalid Login', true, true)
			}
		}
	})

	// Calls embedCreator() once the widgetInfo, widgetInstance, and keepQset have finished loading
	useEffect(() => {
		if (instId && (instanceIsLoading || qSetIsLoading)) {
			// Wait for apiGetWidgetInstance and apiGetQuestionSet to finish fetching
			return
		} else if (widgetInfo) {
			embedCreator(widgetInfo);
		}

	}, [widgetInfo, instanceIsLoading, qSetIsLoading])

	// Embeds the creator
	const embedCreator = (widget) => {
		let creatorPath

		// Show the buttons that interact with the creator
		enableReturnLink()
		setShowActionBar(true)

		setNonEditable(widget.is_editable === '0')

		if (widget.creator.substring(0, 4) === 'http') {
			// allow creator paths to be absolute urls
			creatorPath = widget.creator
		} else {
			// link to the static widget
			creatorPath = window.WIDGET_URL + widget.dir + widget.creator
		}

		setWidgetData({
			loading: false,
			htmlPath: creatorPath + '?' + widget.created_at,
			hasCreatorGuide: widget.creator_guide != '',
			creatorGuideUrl: creatorGuideUrl
		})
	}

  	useEffect(() => {
		if (!widgetData.loading) {
			// setup the postmessage listener
			window.addEventListener('message', onPostMessage, false)

			// cleanup this listener
			return () => {
				window.removeEventListener('message', onPostMessage, false);
			}
		}
	}, [widgetData])

	// Called only if instId exists and the fetch for qset was successful
	useEffect(() => {
		if (creatorReady) {
			if (widgetInstance && (!keepQSet || Object.keys(keepQSet).length == 0)) {
				// If qset has not loaded yet but we know the instance exists, return and wait until qset has loaded
				return;
			} else if (frameRef.current == null) {
				onInitFail('Unable to load widget.')
			} else if (!canPublish && widgetInstance && !widgetInstance.is_draft) {
				onInitFail('Widget type can not be edited by students after publishing.')
			} else {
				if (widgetInstance && (keepQSet || qsetToReload)) {
					// Widget instance exists and qset has loaded
					setStartTime(new Date().getTime());

					if (!widgetInstance.is_draft) {
						setPublishText('Update')
						setUpdateMode(true)
					}

					let qsetToInit;

					if (qsetToReload && Object.keys(qsetToReload).length !== 0) {
						qsetToInit = qsetToReload;
						setQsetToReload(null)
					} else {
						qsetToInit = keepQSet;
					}

					setKeepQSet({
						data: qsetToInit.data,
						version: qsetToInit.version,
					});
		
					let args = [widgetInstance.name, widgetInstance, qsetToInit.data, qsetToInit.version, window.BASE_URL, window.MEDIA_URL];

					sendToCreator('initExistingWidget', args);
					// Reset creator ready
					setCreatorReady(false);
				} else if (widgetInfo && !widgetInstance) {
					// Widget instance does not exist
					// Widget info has loaded
					setStartTime(new Date().getTime());
					let args = [widgetInfo, window.BASE_URL, window.MEDIA_URL];
					sendToCreator('initNewWidget', args);
					// Don't set creatorReady to false in case widgetInstance and/or qset are still loading
				}
			}
		}
	}, [creatorReady, keepQSet, widgetInstance])

	const requestSave = (mode) => {
		// hide dialogs
		setPopup('');
		saveModeRef.current = mode
		setSaveStatus('saving');
		switch (saveModeRef.current) {
			case 'publish':
				setPreviewText('Saving...');
				break
			case 'save':
				setSaveText('Saving...');
				break
		}
		sendToCreator('onRequestSave', [saveModeRef.current])
	}

	// Popup a question importer dialog
	const showQuestionImporter = () => {
		// must be loose comparison
		const types = widgetInfo.meta_data.supported_data
		//the value passed on needs to be a list of one or two elements, i.e.
		//?type=QA or ?type=MC or ?type=QA,MC
		showEmbedDialog(`${window.BASE_URL}questions/import/?type=${encodeURIComponent(types.join())}`)
		return null // else Safari will give the .swf data that it can't handle
	}

	const showQsetHistoryImporter = () => {
		if (showQsetHistoryDialog) {
			setShowQsetHistoryDialog(false);
			hideEmbedDialog();
		} else {
			setShowQsetHistoryDialog(true);
			showEmbedDialog(`${window.BASE_URL}qsets/import/?inst_id=${instId}`)
		}
		return null
	}

	const onPublishPressed = () => {
		if (!!instId && !!widgetInstance && !widgetInstance.is_draft) {
			// Show the Update Dialog
			setPopup('update')
		} else {
			// Show the Publish Dialog
			setPopup('publish')
		}
	}

	const cancelPublish = (e) => {
		setPopup('')
	}

	const cancelPreview = (e) => {
		setPopup('')
	}

	// If Initialization Fails
	const onInitFail = (msg) => {
		toggleHeartbeat(false)
		_alert(msg, 'Failure', true, false)
	}

	// Send messages to the creator
	const sendToCreator = (type, args) => {
		return frameRef.current.contentWindow.postMessage(
			JSON.stringify({ type, data: args }),
			window.STATIC_CROSSDOMAIN
		)
	}

	// build a my-widgets url to a specific widget
	const getMyWidgetsUrl = (instid) => `${window.BASE_URL}my-widgets#${instid}`

	const onPostMessage = (e) => {
		const origin = `${e.origin}/`
		if (origin === window.STATIC_CROSSDOMAIN || origin === window.BASE_URL) {
			const msg = JSON.parse(e.data)
			switch (
				msg.source // currently 'creator-core' || 'media-importer' - can be extended to other sources
			) {
				case 'media-importer':
					// options for media-importer postMessages
					switch (msg.type) {
						// broadcast by the importer when showMediaImporter is called
						// if a file is pre-selected (by direct upload pipeline), go ahead and send it over
						// this behavior only occurs for direct media uploads, bypassing user input
						case 'readyForDirectUpload':
							if (mediaFile) return e.source.postMessage(mediaFile, e.origin)
							else return false
						default:
							return false
					}

				case 'creator-core':
				default:
					// options for creator-core postMessages
					switch (msg.type) {
						case 'start': // The creator notifies us when its ready
							return setCreatorReady(true)
						case 'save': // The creator issued a save request
							return save(msg.data[0], msg.data[1], msg.data[2]) // instanceName, qset
						case 'cancelSave': // the creator canceled a save request
							return onSaveCanceled(msg.data[0]) // msg
						case 'showMediaImporter': // the creator wants to import media
							return showMediaImporter(msg.data)
						case 'directUploadMedia': // the creator is requesting to directly upload a media file, bypassing user input
							return directUploadMedia(msg.data)
						case 'setHeight': // the height of the creator has changed
							return setHeight(`${msg.data[0]}px`)
						case 'alert':
							return _alert(msg.data.msg, msg.data.title, msg.data.fatal)
						default:
							return console.warn(`Unknown message from creator: ${msg.type}`)
					}
			}
		}

		console.warn(`Unknown message from creator: ${origin}`)
	}

	// Changes the Return link's functionality depending on use
	const enableReturnLink = () => {
		if (!!instId) {
			// editing
			setReturnUrl(getMyWidgetsUrl(instId))
			setReturnPlace('My Widgets')
		} else {
			// new
			setReturnUrl(`${window.BASE_URL}widgets`)
			setReturnPlace('Widget Catalog')
		}
	}

	const onPreviewPopupBlocked = (url) => {
		setPopup('blocked')
		setPreviewUrl(url)
	}

	// Show an embedded dialog, as opposed to a popup
	const showEmbedDialog = (url) => (setIframeUrl(url))

	// move the embed dialog off to invisibility
	const hideEmbedDialog = () => {
		setIframeUrl('')
		setEmbedDialogType('embed_dialog')
		setModal(false)
	}

	// Note this is psuedo public as it's exposed to flash
	const showMediaImporter = (types) => {
		showEmbedDialog(`${window.BASE_URL}media/import#${types.join(',')}`)
		setModal(true)
		return null // else Safari will give the .swf data that it can't handle
	}

	// Called by the creator when a direct upload of media is requested - instead of asking user to select one themselves
	// Displays the media importer (which dispatches 'readyForDirectUpload') and pre-selects the mediaFile to be uploaded
	const directUploadMedia = (media) => {
		showMediaImporter(['jpg', 'gif', 'png', 'mp3'])
		setMediaFile(media);
	}

	// save called by the widget creator
	// Note this is psuedo public as it's exposed to flash
	const save = (instanceName, qset, version) => {
		if (version == null) {
			version = 1
		}
		let w = {
			widget_id: widgetId,
			name: instanceName,
			qset: { version, data: qset },
			is_draft: saveModeRef.current !== 'publish',
			inst_id: instId,
		}

		// 'history' is sent from onQsetHistorySelectionComplete to request the current qset trait from the creator
		// since the qset is all we need, no need to save to the DB
		if (saveModeRef.current == 'history') {
			setQsetToBeCached({
				qset,
				version,
			})
			return false
		}

		apiSaveWidget(w).then((inst) => {
			// did we get back an error message?
			if ((inst != null ? inst.msg : undefined) != null) {
				onSaveCanceled(inst)
				setAlertDialog({...alertDialog, fatal: inst.halt, enabled: true});
			} else if (inst != null && inst.id != null) {
				// update this creator's url
				window.location.hash = `#${inst.id}`

				switch (saveModeRef.current) {
					case 'preview':
						var url = `${window.BASE_URL}preview/${inst.id}`
						var popup = window.open(url)
						setInstanceId(inst.id)
						if (popup != null) {
							setTimeout(() => {
								if (!(popup.innerHeight > 0)) {
									return onPreviewPopupBlocked(url)
								}
							}, 200)
						} else {
							onPreviewPopupBlocked(url)
						}
						break
					case 'publish':
						window.location = getMyWidgetsUrl(inst.id)
						break
					case 'save':
						setSaveText('Saved!')
						setPreviewText('Preview');
						sendToCreator('onSaveComplete', [
							inst.name,
							inst.widget,
							inst.qset.data,
							inst.qset.version,
						])
						setInstanceId(inst.id)
						setSaveStatus('saved')
						break
				}
				setTimeout(() => {
					setSaveText('Save Draft')
					setSaveStatus('idle')
				}, 5000)
			}
		})
	}

	// When the Creator cancels a save request
	// Note this is psuedo public as it's exposed to flash
	const onSaveCanceled = (msg) => {
		setSaveText('Can Not Save!')

		if ((msg != null ? msg.msg : undefined) != null) {
			if (msg.halt != null) {
				_alert(
					`Unfortunately, your progress was not saved because ${msg.msg.toLowerCase()}. Any unsaved progress will be lost.`,
					'Invalid Login',
					true,
					true
				)
				return toggleHeartbeat(false)
			}
		} else {
			if (msg) {
				return _alert(
					`Unfortunately your progress was not saved because ${msg.toLowerCase()}`,
					'Hold on a sec',
					false,
					false
				)
			}
		}
	}

	const _alert = (msg, title = 'Warning!', fatal = false, enableLoginButton = false) => {
		setAlertDialog({
			enabled: true,
			msg: msg,
			title: title,
			fatal: fatal,
			enableLoginButton: enableLoginButton,
		})
	}

	const _qsetRollbackConfirmation = (confirm) => {
		setShowActionBar(true)
		setShowRollbackConfirmBar(false)
		setShowQsetHistoryDialog(false)

		if (confirm) {
			setQsetToReload(null)
			return false
		} else {
			// re-apply cached qset saved via onQsetHistorySelectionComplete
			setQsetToReload({
				data: qsetToBeCached.qset,
				version: qsetToBeCached.version,
			})
			sendToCreator('reloadCreator')
		}
	}

	// Exposed to the window object so that popups and frames can use this public functions
	window.Materia = {
		Creator: {
			// Exposed to the question importer screen
			onQuestionImportComplete(questions) {
				hideEmbedDialog()
				if (!questions) {
					return
				}
				// assumes questions is already a JSON string
				questions = JSON.parse(questions)

				//strip id from all imported questions and answers to avoid collisions
				questions.forEach((question) => {
					if (question.answers && question.answers.length > 0) {
						question.answers.forEach((answer) => {
							answer.id = null
						})
					}
					question.id = null
				})

				return sendToCreator('onQuestionImportComplete', [questions])
			},

			// Exposed to the media importer screen
			onMediaImportComplete(media) {
				hideEmbedDialog()

				if (media !== null) {
					// convert the sparce array that was converted into an object back to an array (ie9, you SUCK)
					const anArray = []
					for (let element of Array.from(media)) {
						anArray.push(element)
					}
					return sendToCreator('onMediaImportComplete', [anArray])
				}
			},

			// When a qset is selected from the prior saves list
			onQsetHistorySelectionComplete(qset, version = 1) {
				hideEmbedDialog()

				if (!qset) return false

				// request a save from the widget to grab the current qset state
				// passing 'history' as the save mode short-circuits the save functionality so a new save isn't actually made in the database
				requestSave('history')

				// use initExistingWidget to apply the selected qset
				setQsetToReload({
					data: JSON.parse(qset),
					version: version,
				})
				sendToCreator('reloadCreator')

				setShowActionBar(false)
				setShowRollbackConfirmBar(true)
			},
		}
	}

	let editButtonsRender = null
	if (!updateMode || !nonEditable) {
		editButtonsRender = (
			<span>
				<button id="creatorPreviewBtn" className="edit_button orange" type="button" onClick={()=>requestSave('preview')}><span>{previewText}</span></button>
				<button id="creatorSaveBtn" className={`edit_button orange ${saveStatus}`} type="button" onClick={()=>requestSave('save')}><span>{saveText}</span></button>
			</span>
		)
	}

	let creatorGuideLink = null
	if (widgetData.hasCreatorGuide) {
		creatorGuideLink = (
			<a id="creatorGuideLink" href={widgetData.creatorGuideUrl} target="_blank">Creator's Guide</a>
		)
	}

	let actionBarRender = null
	if (showActionBar) {
		actionBarRender = (
			<section id='action-bar'>
				<a id="returnLink" href={returnUrl}>&larr;Return to {returnPlace}</a>
				{ creatorGuideLink }
				{ instId ? <a onClick={showQsetHistoryImporter}>Save History</a> : '' }
				<a id="importLink" onClick={showQuestionImporter}>Import Questions...</a>
				{ editButtonsRender }
				<div className="dot"></div>
				<button id="creatorPublishBtn"
					className="edit_button green"
					type="button"
					onClick={onPublishPressed}>
					{publishText}
				</button>
			</section>
		)
	}

	let loadingRender = null
	if (
		// iframe hasn't loaded
		widgetData.loading 		
		// widgetInstance isn't loaded
		|| instanceIsLoading 	
		// instance has loaded but qset is still loading
		|| widgetInstance && !!keepQSet && Object.keys(keepQSet).length == 0) {
			loadingRender = (
				<LoadingIcon size='lrg'/>
			)
	}

	let alertDialogRender = null
	if (alertDialog.enabled) {
		alertDialogRender = (
			<Alert
				msg={alertDialog.msg}
				title={alertDialog.title}
				fatal={alertDialog.fatal}
				showLoginButton={alertDialog.enableLoginButton}
				onCloseCallback={() => {
					setAlertDialog({...alertDialog, enabled: false})
				}} />
		)
	}

	let popupRender = null
	switch(popup) {
		case 'blocked':
			popupRender = (
				<div className="preview animate-show">
					<p>Your browser blocked the preview popup, click below to preview the widget.</p>
					<div className="publish_container">
						<a className="cancel_button" onClick={cancelPreview}>Close</a>
						<a href={previewUrl} target="_blank" onClick={cancelPreview} className="action_button green">Open Preview</a>
					</div>
				</div>
			)
			break;
		case 'update':
			popupRender = (
				<div className="publish animate-show">
					<h1>Update Widget</h1>
					<p>Updating this published widget will instantly allow your students to see your changes.</p>

					<div className="publish_container">
						<a className="cancel_button" onClick={cancelPublish}>Cancel</a>
						<a className="action_button green" onClick={() => requestSave('publish')}>Yes, Save Updates</a>
					</div>
				</div>
			)
			break;
		case 'publish':
			if (canPublish) {
				popupRender = (
					<div className="publish animate-show">
						<h1>Publish Widget</h1>
						<p>Publishing removes the "Draft" status of a widget, which grants you the ability to use it in your course and collect student scores &amp; data.</p>
						<div className="publish_container">
							<a className="cancel_button" onClick={cancelPublish}>Cancel</a>
							<a className="action_button green" onClick={() => requestSave('publish')}>Yes, Publish</a>
						</div>
					</div>
				)
			}
			else {
				popupRender = (
					<div className="publish animate-show">
						<h1>Publish Restricted</h1>
						<p>Students are not allowed to publish this widget.</p>
						<p>You can share the widget with a non-student who can publish it for you. Select "Save Draft" and add a non-student as a collaborator on the My Widgets page.</p>

						<div className="publish_container">
							<a className="cancel_button" onClick={cancelPublish}>Cancel</a>
						</div>
					</div>
				)
			}
			break;
	}

	let rollbackConfirmBarRender = null
	if (showRollbackConfirmBar) {
		rollbackConfirmBarRender = (
			<section id="qset-rollback-confirmation-bar">
				<h3>Previewing Prior Save</h3>
				<p>Select <span>Cancel</span> to go back to the version you were working on. Select <span>Keep</span> to edit this version.</p>
				<button data-testid='keep_qset' onClick={() => _qsetRollbackConfirmation(true)}>Keep</button>
				<button onClick={() => _qsetRollbackConfirmation(false)}>Cancel</button>
			</section>
		)
	}


	let noPermissionRender = null
	if (invalid) {
		noPermissionRender = <NoPermission />
	}

	return (
		<div>
			<section className="page" ng-show="loaded">
				{ alertDialogRender }
				{ popupRender }
				{ rollbackConfirmBarRender }
				{ actionBarRender }

				<div className="center">
					<iframe src={ widgetData.htmlPath } 
						title="Widget Embed"
						id='container'
						className='html'
						scrolling='yes'
						style={{
						minWidth: minWidth + 'px',
						minHeight: minHeight + 'px'}}
						ref={frameRef}/>
						{ loadingRender }
				</div>
				<iframe src={ iframeUrl } title="Embed Dialog" className={ iframeUrl ? 'show' : 'hidden' } id={embedDialogType} frameBorder={0} width={675} height={500}></iframe>
			</section>
			{ noPermissionRender }
		</div>
	)
}

export default WidgetCreator
