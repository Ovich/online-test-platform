import { useState, useEffect } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import Image from 'next/image';

import LayoutMain from '../../layout/LayoutMain';
import {Box, Button, IconButton, Stack} from '@mui/material';
import { useSnackbar } from '../../../context/SnackbarContext';
import DataGrid from '../../ui/DataGrid';
import DialogFeedback from '../../feedback/DialogFeedback';

import { Role } from "@prisma/client";
import Authorisation from "../../security/Authorisation";
import AddExamDialog from "../AddExamDialog";
import MainMenu from "../../layout/MainMenu";

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
        label: 'Description',
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
    }
  ]
};

const PageList = () => {
  const { show: showSnackbar } = useSnackbar();

  const [ addDialogOpen, setAddDialogOpen ] = useState(false);
  const [ deleteDialogOpen, setDeleteDialogOpen ] = useState(false);
  const [ examToDelete, setExamToDelete ] = useState(null);

  const { data, error } = useSWR(
    `/api/exams`,
    (...args) => fetch(...args).then((res) => res.json())
  );

  const [ exams, setExams ] = useState(data);

  useEffect(() => {
    setExams(data);
  }, [data]);

  const deleteExam = async () => {
    await fetch(`/api/exams/${examToDelete}`, {
      method: 'DELETE',
    })
    .then((_) => {
      setExams(exams.filter((exam) => exam.id !== examToDelete));
      showSnackbar('Exam deleted', 'success');
    })
    .catch((_) => {
      showSnackbar('Error deleting exam', 'error');
    });
    setExamToDelete(null);
    setDeleteDialogOpen(false);
  }

  return (
      <Authorisation allowRoles={[ Role.PROFESSOR ]}>
        <LayoutMain
            header={ <MainMenu /> }
            subheader={
                <Stack alignItems="flex-end" sx={{ p : 1}}>
                  <Button onClick={() => setAddDialogOpen(true)}>Create a new exam</Button>
                </Stack>
            }
        >
        <Box sx={{ minWidth:'100%' }}>
          {exams && exams.length > 0 && (
            <DataGrid
              header={gridHeader}
              items={exams.map(exam => ({
                label: exam.label,
                description: exam.description,
                createdAt: displayDateTime(exam.createdAt),
                updatedAt: displayDateTime(exam.updatedAt),
                questions: exam.questions?.length,
                meta: {
                  key: exam.id,
                  linkHref: `/exams/${exam.id}/questions/1`,
                  actions:  [(
                    <IconButton key="delete-exam" onClick={(ev) => {
                      ev.preventDefault();
                      ev.stopPropagation();
                      setExamToDelete(exam.id);
                      setDeleteDialogOpen(true);
                    }}>
                      <Image alt="Delete" src="/svg/icons/delete.svg" layout="fixed" width="18" height="18" />
                    </IconButton>
                  )]
                }
              }))
              }
              />
          )}
          <DialogFeedback
                open={deleteDialogOpen}
                title="Delete exam"
                content="Are you sure you want to delete this exam?"
                onClose={() => setDeleteDialogOpen(false)}
                onConfirm={deleteExam}
            />
            <AddExamDialog
                open={addDialogOpen}
                onClose={() => setAddDialogOpen(false)}
                handleAddExam={(exam) => {
                    setExams([exam, ...exams]);
                    setAddDialogOpen(false);
                }}
            />
        </Box>
        </LayoutMain>
      </Authorisation>
  )
}

export default PageList;
