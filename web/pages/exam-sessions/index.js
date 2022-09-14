import { useState, useEffect } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import Image from 'next/image';
import { ExamSessionPhase } from '@prisma/client';
import { Box, Toolbar, Button, IconButton } from '@mui/material';
import MainLayout from '../../components/layout/MainLayout';
import DataGrid from '../../components/ui/DataGrid';
import { useSnackbar } from '../../context/SnackbarContext';
import DialogFeedback from '../../components/feedback/DialogFeedback';
import DisplayPhase from '../../components/exam-session/DisplayPhase';
import LoadingAnimation from '../../components/layout/LoadingAnimation';

const displayDateTime = (date) => {
  const d = new Date(date);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}

const gridHeader = {
  actions: {
    label: 'Actions',
    width: '80px',
  },
  columns: [
    {
        label: 'Label',
        column: { flexGrow: 1, }
    },{
        label: 'Created At',
        column: { width: '160px', }
    },{
        label: 'Updated At',
        column: { width: '160px', }
    },{
        label: 'Questions',
        column: { width: '80px', }
    },{
        label: 'Students',
        column: { width: '80px', }
    },{
        label: 'Phase',
        column: { width: '100px', }
    }
  ]
};

const ExamSessions = () => {

  const { show: showSnackbar } = useSnackbar();

  const [ deleteDialogOpen, setDeleteDialogOpen ] = useState(false);
  const [ examSessionToDelete, setExamSessionToDelete ] = useState(null);

  const { data, error } = useSWR(
    `/api/exam-sessions`, 
    (...args) => fetch(...args).then((res) => res.json())
  );
  
  const [ examSessions, setExamSession ] = useState(data);

  useEffect(() => {
    if(data){
      setExamSession(data);
    }
  }, [data]);

  const deleteExamSession = async () => {
    await fetch(`/api/exam-sessions/${examSessionToDelete}`, {
      method: 'DELETE',
    })
    .then((_) => {
      setExamSession(examSessions.filter((exam) => exam.id !== examSessionToDelete));
      showSnackbar('Exam session deleted', 'success');
    })
    .catch((_) => {
      showSnackbar('Error deleting exam session', 'error');
    });
    setExamSessionToDelete(null);
  }

  const linkPerPhase = (phase, examSessionId) => {
    switch(phase){
      case ExamSessionPhase.DRAFT:
        return `/exam-sessions/${examSessionId}/draft/1`;
      case ExamSessionPhase.IN_PROGRESS:
        return `/exam-sessions/${examSessionId}/in-progress/1`;
      case ExamSessionPhase.GRADING:
        return `/exam-sessions/${examSessionId}/grading/1`;
      case ExamSessionPhase.FINISHED:
        return `/exam-sessions/${examSessionId}/finished`;
      default:
        return `/exam-sessions`;
    }
  }

  if (error) return <div>failed to load</div>
  if (!examSessions) return <LoadingAnimation /> 

  return (
    <MainLayout>
    <Box sx={{ minWidth:'100%' }}>
      <Toolbar disableGutters variant="dense">
        <Link href="/exam-sessions/new">
          <Button>New exam session</Button>
        </Link>
      </Toolbar>
      {examSessions && examSessions.length > 0 && (
        <DataGrid 
          header={gridHeader} 
          items={examSessions.map(examSession => ({
            label: examSession.label,
            createdAt: displayDateTime(examSession.createdAt),
            updatedAt: displayDateTime(examSession.updatedAt),
            questions: examSession.questions.length,
            students: examSession.students.length,
            phase: <DisplayPhase phase={examSession.phase} />,
            meta: {
              key: examSession.id,
              linkHref: linkPerPhase(examSession.phase, examSession.id),
              actions:  [(
                <IconButton key="delete-exam" onClick={(ev) => {
                  ev.preventDefault();
                  ev.stopPropagation();
                  setExamSessionToDelete(examSession.id);
                  setDeleteDialogOpen(true);
                }}>
                  <Image alt="Delete" src="/exam-delete.svg" layout="fixed" width="18" height="18" />
                </IconButton>
              )]
            }
          }))
          } 
          />
      )}
      <DialogFeedback 
          open={deleteDialogOpen}  
          title="Delete exam session"
          content="Are you sure you want to delete this exam session?"
          onClose={() => setDeleteDialogOpen(false)}
          onConfirm={deleteExamSession}
      />
    </Box>
    </MainLayout>
  )
}

export default ExamSessions;