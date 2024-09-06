/**
 * Copyright 2022-2024 HEIG-VD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import React, {
  createContext,
  useContext,
  useCallback,
  useEffect,
  useState,
} from 'react'
import useSWR from 'swr'
import { fetcher } from '../code/utils'
import { useRouter } from 'next/router'
import { useDebouncedCallback } from 'use-debounce'
import AnnotationHighlight from '@/components/evaluations/grading/annotation/AnnotationHighlight'
import { AnnotationState } from '@/components/evaluations/grading/annotation/types'

const AnnotationContext = createContext()

export const useAnnotation = () => useContext(AnnotationContext)

const createAnnotation = async (
  groupScope,
  student,
  question,
  entityType,
  entity,
  annotation,
) => {
  const response = await fetch(`/api/${groupScope}/gradings/annotations`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      student,
      question,
      entityType,
      entity,
      annotation,
    }),
  })
  const data = await response.json()
  return data
}

const updateAnnotation = async (groupScope, annotation) => {
  const response = await fetch(
    `/api/${groupScope}/gradings/annotations/${annotation.id}`,
    {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        annotation,
      }),
    },
  )

  const data = await response.json()
  return data
}

const discardAnnotation = async (groupScope, annotationId) => {
  if (annotationId) {
    await fetch(`/api/${groupScope}/gradings/annotations/${annotationId}`, {
      method: 'DELETE',
    })
  }
}

export const AnnotationProvider = ({
  children,
  annotation: immutableAnnotation,
  readOnly = false,
  student,
  question,
  entityType,
  entity,
}) => {
  const router = useRouter()

  const { groupScope } = router.query

  const doFetch = !readOnly && groupScope && entity?.id

  /* 
      When used in the context of student consultation, the annotation is immutable
      and is supplied as prop immutableAnnotation. The annotation is not managed by the context. It is only used to
      initialize the context state.
      When used in the context of grading, the annotation is mutable its data is managed by the context. The context
      fetches the annotation from the server and updates it when the user changes it.
  */
  const { data: contextAnnotation, mutate } = useSWR(
    doFetch &&
      `/api/${groupScope}/gradings/annotations?entityType=${entityType}&entityId=${entity.id}`,
    doFetch && fetcher,
  )

  const [annotation, setAnnotation] = useState(null)
  const [state, setState] = useState(stateBasedOnAnnotation(contextAnnotation))

  useEffect(() => {
    if (!doFetch) {
      setAnnotation(immutableAnnotation)
      setState(stateBasedOnAnnotation(immutableAnnotation))
    }
  }, [immutableAnnotation, doFetch])

  useEffect(() => {
    if (doFetch) {
      // Context Managed Annotation (Grading)
      setAnnotation(contextAnnotation)
      setState(stateBasedOnAnnotation(contextAnnotation))
    }
  }, [contextAnnotation, doFetch])

  const debouncedUpdateAnnotation = useDebouncedCallback(updateAnnotation, 1000)

  const change = useCallback(
    async (content) => {
      if (readOnly) {
        return
      }
      const updated = {
        ...annotation,
        content,
      }
      setAnnotation(updated)

      if (state === AnnotationState.NOT_ANNOTATED.value) {
        setState(AnnotationState.ANNOTATED.value)
      }

      if (annotation?.id) {
        debouncedUpdateAnnotation(groupScope, updated)
      } else {
        const newAnnotation = await createAnnotation(
          groupScope,
          student,
          question,
          entityType,
          entity,
          updated,
        )
        setAnnotation({
          ...updated,
          id: newAnnotation.id,
        })
      }
    },
    [
      annotation,
      debouncedUpdateAnnotation,
      entity,
      entityType,
      groupScope,
      question,
      readOnly,
      setAnnotation,
      setState,
      state,
      student,
    ],
  )

  const discard = useCallback(async () => {
    if (readOnly) {
      return
    }
    const annotationId = annotation.id
    setAnnotation(null)
    setState(AnnotationState.NOT_ANNOTATED.value)
    await discardAnnotation(groupScope, annotationId)
  }, [groupScope, annotation, readOnly])

  return (
    <AnnotationContext.Provider
      value={{
        readOnly,
        state,
        annotation,
        change,
        discard,
      }}
    >
      <AnnotationHighlight readOnly={readOnly} state={state}>
        {children}
      </AnnotationHighlight>
    </AnnotationContext.Provider>
  )
}

const stateBasedOnAnnotation = (annotation) => {
  return annotation
    ? AnnotationState.ANNOTATED.value
    : AnnotationState.NOT_ANNOTATED.value
}
