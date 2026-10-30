document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.querySelector('.menu-toggle');
  const nav = document.querySelector('.nav-links');
  if (toggle && nav) toggle.addEventListener('click', () => {
    const open = nav.classList.toggle('open');
    toggle.setAttribute('aria-expanded', String(open));
  });
  document.querySelectorAll('.alert-close').forEach(button => button.addEventListener('click', () => button.closest('.alert').remove()));
  const deleteDialog = document.querySelector('.delete-dialog');
  let pendingDeleteForm = null;
  if (deleteDialog) {
    document.querySelectorAll('.delete-form').forEach(form => form.addEventListener('submit', event => {
      event.preventDefault();
      pendingDeleteForm = form;
      deleteDialog.showModal();
    }));
    deleteDialog.addEventListener('close', () => {
      if (deleteDialog.returnValue === 'delete' && pendingDeleteForm) pendingDeleteForm.submit();
      pendingDeleteForm = null;
    });
  }
  const fileInput = document.querySelector('#file-input');
  const dropzone = document.querySelector('.dropzone');
  const label = document.querySelector('#file-label');
  if (fileInput && label) fileInput.addEventListener('change', () => { if (fileInput.files.length) label.textContent = fileInput.files.length === 1 ? fileInput.files[0].name : fileInput.files.length + " files selected"; });
  if (dropzone && fileInput) {
    ['dragenter', 'dragover'].forEach(name => dropzone.addEventListener(name, event => { event.preventDefault(); dropzone.classList.add('dragging'); }));
    ['dragleave', 'drop'].forEach(name => dropzone.addEventListener(name, event => { event.preventDefault(); dropzone.classList.remove('dragging'); }));
    dropzone.addEventListener('drop', event => { if (event.dataTransfer.files.length) { fileInput.files = event.dataTransfer.files; fileInput.dispatchEvent(new Event('change')); } });
  }
});
