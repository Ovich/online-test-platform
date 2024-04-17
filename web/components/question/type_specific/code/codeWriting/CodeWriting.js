import React, { useState } from 'react'
import { Tab, Tabs, Typography } from '@mui/material'
import TabPanel from '@/components/layout/utils/TabPanel'
import TabContent from '@/components/layout/utils/TabContent'
import TestCases from './TestCases'
import SolutionFilesManager from './files/SolutionFilesManager'
import TemplateFilesManager from './files/TemplateFilesManager'
import Sandbox from '../Sandbox'

const CodeWriting = ({ groupScope, questionId, language, onUpdate }) => {

    const [tab, setTab] = useState(1)
  
    return (
      <>
        <Tabs
          value={tab}
          onChange={(ev, val) => setTab(val)}
          aria-label="code tabs"
        >
          <Tab
            label={<Typography variant="caption">Setup</Typography>}
            value={0}
          />
          <Tab
            label={<Typography variant="caption">Solution</Typography>}
            value={1}
          />
          <Tab
            label={<Typography variant="caption">Template</Typography>}
            value={2}
          />
        </Tabs>
        <TabPanel id="setup" value={tab} index={0}>
          <TabContent padding={2} spacing={4}>
            <Sandbox
              groupScope={groupScope}
              questionId={questionId}
              language={language}
              onUpdate={onUpdate}
            />
  
            <TestCases
              groupScope={groupScope}
              questionId={questionId}
              language={language}
              onUpdate={onUpdate}
            />
          </TabContent>
        </TabPanel>
        <TabPanel id="solution" value={tab} index={1}>
          <TabContent>
            <SolutionFilesManager
              groupScope={groupScope}
              questionId={questionId}
              language={language}
              onUpdate={onUpdate}
            />
          </TabContent>
        </TabPanel>
        <TabPanel id="template" value={tab} index={2}>
          <TabContent>
            <TemplateFilesManager
              groupScope={groupScope}
              questionId={questionId}
              onUpdate={onUpdate}
            />
          </TabContent>
        </TabPanel>
      </>
    )
}

export default CodeWriting;